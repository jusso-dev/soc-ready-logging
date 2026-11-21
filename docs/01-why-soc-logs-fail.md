# 01 — Why Custom Application Logs Usually Fail Government SOCs

When a government agency buys or commissions custom software, security logging is almost always a mandatory requirement ("must integrate with our SIEM and align to the ACSC ISM and OWASP"). Yet in practice, SOC onboarding fails or stalls for weeks—and often ends with the SOC quietly dropping the application's logs into cold storage or ignoring them completely.

This guide explains the **seven failure modes** SOC teams see over and over again, and how this repository eliminates them with minimal vendor engineering effort.

---

## The Vendor vs. SOC Disconnect

Application developers normally write logs for **debugging and uptime**. SOC analysts consume logs for **threat detection, triage, and forensic reconstruction**. Those two goals pull in opposite directions when everything is dumped into one undifferentiated stdout stream:

| What developers usually emit | What a Government SOC actually needs |
|---|---|
| Free-text strings (`"User failed login"`) | Strict single-line JSON (NDJSON) with stable field names |
| Local timestamps (`21/11/2026 5:10 PM`) | UTC ISO-8601 (`2026-11-21T06:10:01.120Z`) from NTP-synced hosts |
| Every `/healthz`, CSS asset, and SQL query | Only security-relevant state changes, auth, authz, data & tamper events |
| Proxy IP (`10.0.0.4`) instead of client IP | True client IP + `correlation_id` to join WAF, IdP, app, and DB logs |
| Generic `ERROR` with a 60-line stack trace | Concise security event (`authz_fail`, `crypto_verification_fail`) + reason code |
| Raw request headers, JWTs, or citizen PII | Zero secrets, redacted/hashed tokens, privacy-safe identifiers |
| "Just parse our stdout" | Explicit two-stream separation + documented event catalog + starter KQL/Sigma rules |

---

## The Seven Common Failure Modes

### 1. The "Log Everything" Ingestion Trap
Sending `DEBUG`, `TRACE`, Kubernetes readiness probes (`/healthz`, `/readyz`), static asset fetches, and verbose ORM SQL logs into a SIEM (such as Microsoft Sentinel or Splunk) explodes ingestion costs (often $3–$6+ AUD per GB ingested and retained for 12+ months) while burying real attacks under 99% noise. ACSC's *Priority Logs for SIEM Ingestion* explicitly warns against dumping raw operational logs straight into the SIEM.

### 2. Missing the "Who, What, Where, Outcome" Minimum (ISM-0585)
A log line like `Access denied to record` is useless during an incident. Without **immutable actor ID**, **source IP**, **target resource/classification**, **UTC timestamp**, **host/component**, and **outcome**, an analyst cannot tell whether it was a legitimate user hitting a UI bug or a compromised account exfiltrating `OFFICIAL:Sensitive` records.

### 3. Unbounded Event Names and Schema Drift
If sprint 1 logs `"Login failed"`, sprint 2 changes it to `"Auth error: bad pw"`, and sprint 3 renames `userId` to `uid`, every SIEM detection rule silently breaks. Using a fixed **OWASP Logging Vocabulary** event catalog (`authn_login_fail`, `authz_fail`, `priv_role_assigned`) with automated CI schema checks prevents silent detection decay.

### 4. Secrets and Regulated PII Leaking into SIEMs
SIEMs are broad-access forensic platforms with long retention (12+ months under ACSC ISM-1988 and National Archives obligations). Accidentally logging `Authorization: Bearer ...` headers, session cookies, API keys, passwords, Tax File Numbers (TFNs), Medicare numbers, or full citizen forms turns the SIEM into a credential vault and creates a Privacy Act / NDB breach risk.

### 5. Unsanitized Log Injection (CWE-117)
If an attacker submits a username containing `\n` or CRLF characters into a plain-text logger, they can forge fake `authn_login_success` entries or break line-oriented log shippers. Structured JSON serialization + control-character sanitization closes this completely.

### 6. No Separation Between Operational Failures and Security Events
A database timeout (`503`) and a forged JWT signature (`crypto_verification_fail`) should not land in the same bucket with the same severity. Operational telemetry belongs in APM/observability tools (Application Insights, Datadog, Prometheus/Loki); **security events** belong on a dedicated, schema-enforced `stream: "security"` channel.

### 7. No Day-1 SOC Handoff Artefacts
Even well-structured logs sit unmonitored if the SOC has to reverse-engineer what each event means, what constitutes normal volume, and which fields map to Sentinel/Splunk. Handing over a concise **SOC Handoff Pack** (event catalog, sample NDJSON, expected baselines, and starter detection rules) cuts onboarding time from months to days.

---

## The Low-Effort Solution

You do **not** need a massive custom logging framework to get this right:

1. **Adopt one small canonical JSON schema** (`schemas/security-event.schema.json`).
2. **Split your logs into two streams**: `stream: "security"` -> SIEM; everything else -> operational log store / data lake.
3. **Emit the ~15–32 high-value OWASP-prefixed events** that apply to your app (`schemas/event-catalog.json`).
4. **Wrap a single thin `SecurityLogger` helper** (see `examples/` for TypeScript, Python, C#/.NET, and Go) that enforces redaction, UTC timestamps, and CRLF sanitization automatically.
5. **Gate pull requests with `scripts/validate_logs.py` and `scripts/score_signal_noise.py`**, or install the `skills/` in this repo so your AI coding agents audit, implement, verify, and generate the SOC Handoff Pack for you.
