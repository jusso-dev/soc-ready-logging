#!/usr/bin/env python3
"""Static codebase scanner for SOC-ready security logging hygiene.

Scans TS/JS, Python, C#, Go, and Java source files for:
  - High-risk secret / PII logging calls (passwords, tokens, headers, raw bodies, TFNs)
  - Unstructured stdout logging (console.log, print, Console.WriteLine, fmt.Println)
  - Likely SIEM noise logging (healthz/readyz/metrics/static asset logs)
  - Presence vs. absence of canonical OWASP security events from schemas/event-catalog.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "schemas" / "event-catalog.json"

SUPPORTED_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".cs", ".go", ".java"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "bin", "obj", "target", "__pycache__", ".next"}

LOG_CALL_RE = re.compile(
    r"\b(console\.(log|debug|info|warn|error)|logger\.\w+|logging\.\w+|_logger\.Log\w+|"
    r"slog\.\w+|log\.(Print\w*|Info\w*|Warn\w*|Error\w*|Debug\w*)|print\(|Console\.WriteLine|fmt\.Print\w*)\s*\(",
    re.IGNORECASE,
)

UNSTRUCTURED_RE = re.compile(r"\b(console\.log|console\.debug|print|Console\.WriteLine|fmt\.Println|fmt\.Printf)\s*\(")

SENSITIVE_LOG_ARG_RE = re.compile(
    r"\b(password|passwd|pwd|secret|authorization|bearer|cookie|access_token|refresh_token|"
    r"api_key|apikey|private_key|tfn|medicare|credit_card|cvv|req\.body|request\.body|req\.headers|request\.headers)\b",
    re.IGNORECASE,
)

NOISE_LOG_RE = re.compile(r"(/healthz?|/readyz?|/livez?|/metrics|\.css\b|\.js\b|favicon\.ico)", re.IGNORECASE)

BOUNDARY_SIGNALS = {
    "authentication": re.compile(r"\b(login|signin|sign_in|authenticate|oidc|saml|jwt|mfa|totp|webauthn)\b", re.IGNORECASE),
    "authorization": re.compile(r"\b(403|forbidden|authorize|permission|rbac|hasRole|isAdmin)\b", re.IGNORECASE),
    "privilege_or_iam": re.compile(r"\b(assignRole|grantRole|createUser|deleteUser|impersonat)\b", re.IGNORECASE),
    "data_export": re.compile(r"\b(exportCsv|bulkExport|downloadReport|exportData|text/csv)\b", re.IGNORECASE),
}


def load_catalog() -> List[Dict[str, Any]]:
    if not CATALOG_PATH.exists():
        return []
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8")).get("events", [])


def iter_source_files(target_dir: Path) -> List[Path]:
    files: List[Path] = []
    for path in target_dir.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTS:
            files.append(path)
    return sorted(files)


def audit_directory(target_dir: Path) -> Dict[str, Any]:
    catalog = load_catalog()
    catalog_names: Set[str] = {e["event"] for e in catalog}
    detected_events: Set[str] = set()
    detected_boundaries: Set[str] = set()
    findings: List[Dict[str, Any]] = []

    files = iter_source_files(target_dir)
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel_path = str(file_path.relative_to(target_dir))

        for ev_name in catalog_names:
            if ev_name in text:
                detected_events.add(ev_name)

        for domain, b_re in BOUNDARY_SIGNALS.items():
            if b_re.search(text):
                detected_boundaries.add(domain)

        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "*", "/*")):
                continue
            if LOG_CALL_RE.search(line):
                if SENSITIVE_LOG_ARG_RE.search(line) and "REDACTED" not in line:
                    findings.append(
                        {
                            "severity": "HIGH",
                            "rule": "potential_secret_or_pii_log",
                            "file": rel_path,
                            "line": lineno,
                            "snippet": stripped[:140],
                            "advice": "Never log credentials, tokens, headers, raw request bodies, or regulated PII. Redact or omit.",
                        }
                    )
                if NOISE_LOG_RE.search(line):
                    findings.append(
                        {
                            "severity": "MEDIUM",
                            "rule": "potential_siem_noise",
                            "file": rel_path,
                            "line": lineno,
                            "snippet": stripped[:140],
                            "advice": "Keep health probes, metrics, and static asset requests out of the SOC security stream.",
                        }
                    )
                if UNSTRUCTURED_RE.search(line):
                    findings.append(
                        {
                            "severity": "LOW",
                            "rule": "unstructured_stdout_logging",
                            "file": rel_path,
                            "line": lineno,
                            "snippet": stripped[:140],
                            "advice": "Replace ad-hoc stdout prints with structured JSON logging and explicit stream separation.",
                        }
                    )

    expected_by_boundary = {
        "authentication": ["authn_login_success", "authn_login_fail", "authn_mfa_fail"],
        "authorization": ["authz_fail"],
        "privilege_or_iam": ["priv_role_assigned", "user_created"],
        "data_export": ["data_bulk_export"],
    }
    missing_recommended: List[str] = []
    for boundary in sorted(detected_boundaries):
        for ev in expected_by_boundary.get(boundary, []):
            if ev not in detected_events:
                missing_recommended.append(ev)
    if "sys_logging_heartbeat" not in detected_events:
        missing_recommended.append("sys_logging_heartbeat")

    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    return {
        "target": str(target_dir),
        "files_scanned": len(files),
        "detected_security_boundaries": sorted(detected_boundaries),
        "detected_canonical_events": sorted(detected_events),
        "missing_recommended_events": missing_recommended,
        "summary": {"HIGH": high_count, "MEDIUM": med_count, "LOW": low_count},
        "findings": findings,
    }


def render_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"# Codebase Security Logging Audit: `{report['target']}`",
        "",
        f"- **Source files scanned:** `{report['files_scanned']}`",
        f"- **Findings:** `{s['HIGH']}` HIGH | `{s['MEDIUM']}` MEDIUM | `{s['LOW']}` LOW",
        f"- **Detected security boundaries:** {', '.join(report['detected_security_boundaries']) or 'none detected'}",
        f"- **Implemented canonical events:** {', '.join(report['detected_canonical_events']) or 'none detected'}",
        f"- **Missing recommended events:** {', '.join(report['missing_recommended_events']) or 'none'}",
        "",
    ]
    if report["findings"]:
        lines.extend(
            [
                "## Findings",
                "",
                "| Severity | Rule | Location | Advice |",
                "|---|---|---|---|",
            ]
        )
        for f in report["findings"][:50]:
            lines.append(f"| **{f['severity']}** | `{f['rule']}` | `{f['file']}:{f['line']}` | {f['advice']} |")
    else:
        lines.append("No static logging hygiene issues detected.")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static codebase audit for SOC-ready security logging hygiene.")
    parser.add_argument("target", type=Path, help="Path to application source directory")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit 1 if any HIGH severity finding exists")
    args = parser.parse_args(argv)

    if not args.target.exists():
        print(f"Error: path not found: {args.target}", file=sys.stderr)
        return 2

    report = audit_directory(args.target)

    if args.as_json:
        print(json.dumps(report, indent=2))
    elif args.markdown:
        print(render_markdown(report))
    else:
        s = report["summary"]
        print(f"Scanned {report['files_scanned']} files in {report['target']}")
        print(f"  Findings: {s['HIGH']} HIGH | {s['MEDIUM']} MEDIUM | {s['LOW']} LOW")
        print(f"  Canonical events found: {', '.join(report['detected_canonical_events']) or 'none'}")
        print(f"  Missing recommended events: {', '.join(report['missing_recommended_events']) or 'none'}")
        for f in report["findings"][:25]:
            print(f"  [{f['severity']}] {f['file']}:{f['line']} ({f['rule']}) -> {f['advice']}")

    if args.fail_on_high and report["summary"]["HIGH"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
