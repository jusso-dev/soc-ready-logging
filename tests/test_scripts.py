"""Automated verification suite for soc-ready-logging scripts, schemas, examples, and skills."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
EXAMPLES_PY_DIR = REPO_ROOT / "examples" / "python"

sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(EXAMPLES_PY_DIR))

import audit_repo_logging  # noqa: E402
import generate_soc_handoff  # noqa: E402
import generate_test_events  # noqa: E402
import score_signal_noise  # noqa: E402
import security_logger  # noqa: E402
import validate_logs  # noqa: E402


class TestSchemasAndCatalog(unittest.TestCase):
    def test_schema_and_catalog_are_valid_json(self) -> None:
        schema = json.loads((REPO_ROOT / "schemas" / "security-event.schema.json").read_text(encoding="utf-8"))
        catalog = json.loads((REPO_ROOT / "schemas" / "event-catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.0.0")
        events = catalog["events"]
        self.assertGreaterEqual(len(events), 30)
        names = [e["event"] for e in events]
        self.assertEqual(len(names), len(set(names)), "Duplicate event names in catalog")


class TestValidateAndScoreLogs(unittest.TestCase):
    def test_golden_valid_events_pass_strict(self) -> None:
        valid_path = REPO_ROOT / "schemas" / "examples" / "valid-events.ndjson"
        report = validate_logs.validate_file(valid_path, strict=True)
        self.assertTrue(report["passed"], f"Expected valid-events to pass: {report['errors']}")
        self.assertEqual(report["error_count"], 0)

        score_report = score_signal_noise.score_file(valid_path)
        self.assertEqual(score_report["score"], 100.0)
        self.assertEqual(score_report["grade"], "A")

    def test_anti_patterns_fail_with_expected_findings(self) -> None:
        bad_path = REPO_ROOT / "schemas" / "examples" / "anti-patterns.ndjson"
        report = validate_logs.validate_file(bad_path, strict=True)
        self.assertFalse(report["passed"])
        codes = {e["code"] for e in report["errors"]}
        self.assertIn("secret_or_pii_leak", codes)
        self.assertIn("sensitive_key_unredacted", codes)
        self.assertIn("cwe_117_log_injection", codes)
        self.assertIn("noise_contamination", codes)

        score_report = score_signal_noise.score_file(bad_path)
        self.assertLess(score_report["score"], 50.0)


class TestSyntheticEventGenerator(unittest.TestCase):
    def test_generated_all_scenarios_validate_strict_and_score_100(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "synthetic.ndjson"
            rc = generate_test_events.main(
                ["--scenario", "all", "--app-id", "gov-test-portal", "--environment", "uat", "--out", str(out_file)]
            )
            self.assertEqual(rc, 0)
            validation = validate_logs.validate_file(out_file, strict=True)
            self.assertTrue(validation["passed"], f"Validation errors: {validation['errors']}")
            score_report = score_signal_noise.score_file(out_file)
            self.assertEqual(score_report["score"], 100.0)


class TestPythonReferenceLogger(unittest.TestCase):
    def test_redaction_and_cwe117_protection(self) -> None:
        emitted: list[str] = []
        logger = security_logger.SecurityLogger(
            app_id="gov-ref-app",
            app_name="Reference App",
            environment="test",
            version="1.2.3",
            sink=emitted.append,
        )
        logger.emit(
            event="authn_login_fail",
            category="authentication",
            severity="WARN",
            outcome="failure",
            actor={
                "type": "user",
                "id": "usr-001",
                "username": "alice\n2026-11-21T00:00:00Z INFO authn_login_success admin",
                "session_id_hash": security_logger.hash_session_id("raw-cookie-value", "salt"),
            },
            source={"ip": "203.0.113.5", "user_agent": "Mozilla\x1b[31m\r\nFake"},
            reason="invalid_credentials",
            message="Failed login with Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk12345",
            details={"password": "SuperSecretPassword!", "tfn": "123 456 789", "auth_method": "oidc_entra"},
        )
        logger.emit_heartbeat(interval_seconds=900, dropped_events=0)

        self.assertEqual(len(emitted), 2)
        for line in emitted:
            self.assertNotIn("\n", line)
            self.assertNotIn("\r", line)
            self.assertNotIn("SuperSecretPassword!", line)
            self.assertNotIn("123 456 789", line)
            self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", line)

        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "ref.ndjson"
            log_file.write_text("\n".join(emitted) + "\n", encoding="utf-8")
            validation = validate_logs.validate_file(log_file, strict=True)
            self.assertTrue(validation["passed"], f"Reference logger failed validation: {validation['errors']}")


class TestRepoAuditAndHandoffGenerator(unittest.TestCase):
    def test_static_audit_detects_hazards_and_missing_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app_dir = Path(tmp)
            (app_dir / "auth.ts").write_text(
                "\n".join(
                    [
                        "export function login(req: any) {",
                        "  console.log('GET /healthz ok');",
                        "  logger.info('login payload', { password: req.body.password, authorization: req.headers });",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            report = audit_repo_logging.audit_directory(app_dir)
            self.assertGreaterEqual(report["summary"]["HIGH"], 1)
            self.assertGreaterEqual(report["summary"]["MEDIUM"], 1)
            self.assertIn("authn_login_fail", report["missing_recommended_events"])

    def test_handoff_pack_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_md = Path(tmp) / "SOC-HANDOFF-PACK.md"
            rc = generate_soc_handoff.main(
                [
                    "--app-id",
                    "gov-grants-portal",
                    "--app-name",
                    "Grants Portal",
                    "--from-ndjson",
                    str(REPO_ROOT / "schemas" / "examples" / "valid-events.ndjson"),
                    "--out",
                    str(out_md),
                ]
            )
            self.assertEqual(rc, 0)
            content = out_md.read_text(encoding="utf-8")
            self.assertIn("gov-grants-portal", content)
            self.assertIn("authn_login_success_after_fail", content)
            self.assertIn("sys_logging_heartbeat", content)


class TestAgentSkillsAndInstaller(unittest.TestCase):
    def test_all_skills_have_valid_frontmatter(self) -> None:
        skills_dir = REPO_ROOT / "skills"
        skill_folders = sorted(p for p in skills_dir.iterdir() if p.is_dir() and p.name.startswith("soc-"))
        self.assertEqual(len(skill_folders), 4)
        for folder in skill_folders:
            skill_md = folder / "SKILL.md"
            self.assertTrue(skill_md.exists(), f"Missing SKILL.md in {folder}")
            text = skill_md.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\n"), f"Missing YAML frontmatter in {skill_md}")
            self.assertIn(f"name: {folder.name}", text)
            self.assertIn("description:", text)

    def test_install_skills_script_copies_to_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [
                    "bash",
                    str(SCRIPTS_DIR / "install-skills.sh"),
                    "--target",
                    "agents",
                    "--scope",
                    "project",
                    "--project-dir",
                    tmp,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            installed = Path(tmp) / ".agents" / "skills"
            for name in ("soc-logging-audit", "soc-logging-implement", "soc-logging-verify", "soc-handoff-pack"):
                self.assertTrue((installed / name / "SKILL.md").exists(), f"Skill {name} not installed")


if __name__ == "__main__":
    unittest.main()
