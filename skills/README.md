# Portable AI Agent Skills for SOC-Ready Security Logging

These 4 skills follow the open **Agent Skills (`SKILL.md`)** specification and work across **Claude Code**, **Codex**, **Cursor**, **Antigravity**, **GitHub Copilot**, and **OpenCode**.

They let custom software vendor teams go from zero (or noisy, non-compliant logs) to **OWASP + ACSC ISM aligned, high-value, low-noise SOC telemetry** in minutes rather than weeks.

## Included Skills

| Skill | When to Use | What It Does |
|---|---|---|
| [`soc-logging-audit`](./soc-logging-audit/SKILL.md) | First step on any existing codebase | Finds missing authn/authz/IAM/export/tamper hooks, SIEM noise (healthz, debug, static), secret/PII log leaks, and CWE-117 injection hazards. |
| [`soc-logging-implement`](./soc-logging-implement/SKILL.md) | Adding or upgrading security logging | Implements a minimal two-stream `SecurityLogger` wrapper (TS, Python, C#/.NET, Go, Java) with canonical schema, automatic redaction, UTC timestamps, and trusted-proxy IP handling. |
| [`soc-logging-verify`](./soc-logging-verify/SKILL.md) | Testing & CI/CD hardening | Writes positive & negative tests (redaction, CWE-117 injection), validates emitted NDJSON (`validate_logs.py --strict`), and checks Signal-to-Noise score (`>= 90/100`). |
| [`soc-handoff-pack`](./soc-handoff-pack/SKILL.md) | UAT / ATO / SOC onboarding | Generates the Day-1 Government SOC Handoff Pack (`docs/SOC-HANDOFF-PACK.md`), implemented event catalogue, golden sample NDJSON, and starter Sentinel KQL / Sigma / SPL rules. |

---

## One-Command Installation

Clone or download this repository, then install into your vendor project or user profile:

```bash
# Universal project-local (.agents/skills)
./scripts/install-skills.sh --target agents --scope project --project-dir /path/to/vendor-app

# Claude Code (user-wide or project-local)
./scripts/install-skills.sh --target claude --scope user

# Codex / Cursor / Antigravity / Copilot / OpenCode
./scripts/install-skills.sh --target codex --scope project --project-dir /path/to/vendor-app
./scripts/install-skills.sh --target cursor --scope project --project-dir /path/to/vendor-app
./scripts/install-skills.sh --target antigravity --scope user
./scripts/install-skills.sh --target copilot --scope project --project-dir /path/to/vendor-app
./scripts/install-skills.sh --target opencode --scope project --project-dir /path/to/vendor-app

# Or install into .agents, .claude, and .cursor in one go for mixed teams:
./scripts/install-skills.sh --target all-project --project-dir /path/to/vendor-app
```

---

## Recommended Vendor Agent Workflow

Once installed, run these four prompts in order inside your application repo:

1. *"Use `soc-logging-audit` to audit this repo's logging for OWASP and ACSC SOC readiness."*
2. *"Use `soc-logging-implement` to implement the two-stream SecurityLogger and wire all P1 security boundaries."*
3. *"Use `soc-logging-verify` to write contract, redaction, and CWE-117 tests and verify our Signal-to-Noise score is >= 90."*
4. *"Use `soc-handoff-pack` to generate our Day-1 Government SOC Handoff Pack and starter Sentinel KQL / Sigma detections."*
