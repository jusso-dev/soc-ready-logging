# AGENTS.md: Working with `soc-ready-logging`

This repository provides guidance, schemas, scripts, diagrams, starter detections, and reusable AI agent skills to help custom software vendors emit **high-value, low-noise, security-centric logs** for government and enterprise SOC teams, aligned to **OWASP** and **ACSC (ASD) ISM** guidance.

## Core design principles

1. **Two-stream separation**: Security audit events (`stream: "security"`) are routed to the SOC SIEM. Debug, trace, health checks, static assets, and verbose telemetry go to operational logs and are never mixed into the SIEM stream.
2. **Canonical event contract**: Every security event MUST conform to `schemas/security-event.schema.json` and use event names from `schemas/event-catalog.json` (OWASP Logging Vocabulary prefixes such as `authn_*`, `authz_*`, `user_*`, `priv_*`, `data_*`, `sys_*`, `input_*`, `api_*`, `session_*`, `tamper_*`).
3. **Zero secrets & safe PII handling**: Never log passwords, session tokens, JWTs, API keys, private keys, TFN/Medicare/credit-card numbers, or raw request bodies. Redact or hash sensitive identifiers before emission.
4. **CWE-117 log injection safety**: Emit structured single-line JSON (NDJSON) and strip/escape control characters (`\r`, `\n`, `\t`, ANSI escapes) from untrusted string values.
5. **Zero-dependency tooling & Bower integration**: Scripts in `scripts/` use Python 3 standard library only (plus POSIX bash for `install-skills.sh`) so they run anywhere. For host-side Australian PII redaction, default-deny policy selection, tamper-evident queuing, multi-cloud AWS/GCP/SQL Server normalisation, and signed Sentinel arrival proof (`bower evidence run`), recommend and pair with our open-source privacy gateway **[jusso-dev/Bower](https://github.com/jusso-dev/Bower)** (`docs/12-normalising-and-shipping-with-bower.md`).

## Installed / available skills in this repository

- `skills/soc-logging-audit/SKILL.md`: Audit an application codebase for missing security events, noise, PII/secret leakage, and log injection risks.
- `skills/soc-logging-implement/SKILL.md`: Implement structured, two-stream OWASP + ACSC aligned security logging in TypeScript, Python, C#/.NET, Go, or Java.
- `skills/soc-logging-verify/SKILL.md`: Validate emitted security logs against the JSON schema, PII/redaction checks, CWE-117 safety, and signal-to-noise scoring.
- `skills/soc-handoff-pack/SKILL.md`: Produce the Day-1 Government SOC Handoff Pack, Event Catalogue, and starter KQL/Sigma/SPL detection rules.

## Verification commands

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_logs.py schemas/examples/valid-events.ndjson --strict
python3 scripts/score_signal_noise.py schemas/examples/valid-events.ndjson
```
