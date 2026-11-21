# Vendor AI Agent Prompt Pack (For Tools Without Native Skill Loading)

If your team uses Claude Code, Codex, Cursor, Antigravity, GitHub Copilot, or OpenCode, install the portable skills directly using `./scripts/install-skills.sh` (see [`skills/README.md`](../skills/README.md)).

If you are using a web chat or IDE assistant without skill loading, copy-paste these 4 sequential prompts to achieve the exact same result with minimal effort.

---

## Prompt 1 — Audit Existing Codebase
```text
Audit this repository's logging against OWASP Logging Cheat Sheet, OWASP ASVS V16, and ACSC ISM System Monitoring (ISM-0585, ISM-0988, ISM-1228, ISM-1405).
1. Identify every authentication, MFA, authorization (403), user lifecycle, privilege change, API key, sensitive data export/delete, security config, and crypto verification path—and note which ones lack structured security events.
2. Flag any noisy logging that would pollute a SOC SIEM (health checks, static assets, DEBUG/TRACE, per-request valid-JWT logs, raw stack traces).
3. Flag any security hazards: logging passwords, Bearer/JWT tokens, cookies, API keys, raw request bodies, regulated PII (TFN/Medicare/credit cards), or plain-text string interpolation vulnerable to CWE-117 log injection.
Output a prioritized remediation table with exact file paths and line numbers.
```

## Prompt 2 — Implement Two-Stream SOC-Ready Security Logger
```text
Implement a lightweight, zero-bloat SecurityLogger wrapper in this repo following the canonical schema in `soc-ready-logging/schemas/security-event.schema.json`:
- Enforce two-stream separation: emit `stream: "security"` single-line JSON (NDJSON) for SOC SIEM events, keeping debug/health/perf logs on the operational logger.
- Require fields: schema_version ("1.0.0"), timestamp (UTC ISO-8601 Z), stream ("security"), event (OWASP prefix like authn_login_fail, authz_fail, priv_role_assigned, data_bulk_export, crypto_verification_fail, sys_logging_heartbeat), severity (INFO|WARN|HIGH|CRITICAL), outcome (success|failure|blocked|unknown), app, actor, source (true client IP from trusted proxy), correlation_id, and concise message.
- Automatically redact sensitive keys (password, secret, token, authorization, cookie, api_key, tfn, medicare, credit_card) and scrub JWT/Bearer/PEM regex patterns.
- Strip ASCII control characters (\r, \n, \t, ANSI escapes) to prevent CWE-117 log injection.
- Wire the wrapper into all P1 security boundaries identified in the audit without adding noisy per-request logging.
```

## Prompt 3 — Write Automated Contract & Hygiene Tests
```text
Add automated tests proving our security logger meets OWASP and ACSC SOC requirements:
1. Positive tests verifying authn_login_fail, authn_login_success_after_fail, authz_fail, priv_role_assigned, data_bulk_export, and sys_logging_heartbeat emit valid NDJSON matching `schemas/security-event.schema.json`.
2. Negative redaction tests confirming passwords, Bearer JWTs, API keys, and TFNs are replaced with [REDACTED].
3. Negative CWE-117 log-injection tests confirming newline/CRLF payloads in username or User-Agent cannot forge a second log line.
4. Capture test output to NDJSON and validate it with `validate_logs.py --strict` and `score_signal_noise.py` (target score >= 90/100).
```

## Prompt 4 — Generate the Day-1 Government SOC Handoff Pack
```text
Generate `docs/SOC-HANDOFF-PACK.md` for this application based on the actual security events implemented in the codebase:
- Document app.id, environments, hosting, IdP, transport mechanism, trusted-proxy client IP extraction, and heartbeat interval.
- List every emitted security event, its category, default severity, trigger condition, and MITRE ATT&CK / ACSC ISM mapping.
- Document known service accounts and benign batch jobs to prevent Day-1 false positives.
- Include starter Microsoft Sentinel KQL and Sigma detection queries matching our exact `app.id` and event names.
```
