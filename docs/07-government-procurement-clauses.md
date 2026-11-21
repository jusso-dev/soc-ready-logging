# 07: Government Procurement, RFP & Acceptance Clauses

Most vendor logging failures start in procurement: the RFT/SOW simply says *"the solution must support audit logging and SIEM integration"*. That vague sentence gives vendors zero clarity and leaves the agency paying change-request fees later to fix noisy, unparseable logs.

Government buyers and architects can copy-paste the clauses below directly into **RFPs, Statements of Work (SOWs), Solution Architecture Designs (SADs), and Definition-of-Done (DoD) gates**.

---

## Copy-Paste RFP / SOW Security Logging Requirements

> ### Security Event Logging & SOC Readiness
>
> 1. **Two-Stream Separation**: The vendor MUST separate security audit events (`stream: "security"`) from operational, debug, health-check, and performance telemetry. Operational and debug logs MUST NOT be mixed into the SIEM security stream.
> 2. **Structured Schema & OWASP Taxonomy**: All security events MUST be emitted as single-line UTF-8 JSON (NDJSON) conforming to the canonical schema (`schemas/security-event.schema.json`) using standardised OWASP Logging Vocabulary event identifiers (`authn_*`, `authz_*`, `user_*`, `priv_*`, `data_*`, `config_*`, `crypto_*`, `sys_*`, `tamper_*`).
> 3. **ACSC ISM Alignment**: Every security event MUST include an NTP-synchronised UTC ISO-8601 timestamp (`ISM-0988`), immutable actor identifier, true client IP address, target resource/classification where applicable, hosting component/hostname, outcome, correlation ID, and concise human-readable description (`ISM-0585`).
> 4. **Zero Secrets, Safe PII & Log Injection Prevention**: Security logs MUST NOT contain passwords, session cookies, JWTs, API keys, private keys, or unnecessary regulated PII (including TFNs, Medicare numbers, or payment card numbers). All untrusted inputs MUST be sanitised against CWE-117 log injection (control characters stripped/escaped) and serialised via a structured JSON encoder.
> 5. **Signal-to-Noise Gate**: Prior to UAT exit and each major release, a representative staging log capture MUST pass automated schema validation (`validate_logs.py --strict`) with zero secret/PII/injection findings and achieve a Signal-to-Noise score of `>= 90/100` (`score_signal_noise.py`).
> 6. **Tamper Evidence & Pipeline Heartbeat**: Security logs MUST be shipped out-of-process to the agency's centralised SIEM (`ISM-1405`) without granting the application runtime permission to modify or delete remote audit records (`ISM-1815`). The application MUST emit a periodic `sys_logging_heartbeat` event (every 15–60 minutes) to detect silent ingestion dropouts.
> 7. **Day-1 SOC Handoff Pack**: Prior to Authority to Operate (ATO) / Go-Live, the vendor MUST deliver a completed SOC Handoff Pack containing the implemented event catalogue, golden NDJSON samples, expected volume baselines, known service/automation accounts, and starter SIEM detection queries (Sigma / KQL / SPL).

---

## Procurement Evaluation Questions for Vendors

Ask bidders these five concrete questions (their answers immediately reveal maturity):

1. *Can your application route security audit events separately from debug/health-check logs without custom SIEM regex drops?*
2. *Show us a real JSON sample of a failed login, an authorisation denial (HTTP 403), and a privilege change from your product.*
3. *How do you guarantee in CI/CD that credentials, Bearer tokens, and citizen PII cannot leak into security logs?*
4. *How does your application preserve the true client IP and request correlation ID behind an agency WAF / reverse proxy?*
5. *How will our SOC know within 90 minutes if your application stops sending logs?*

---

## Open-Source Reference Gateway for RFPs: [Bower](https://github.com/jusso-dev/Bower)

Government buyers can cite **[jusso-dev/Bower](https://github.com/jusso-dev/Bower)** ([guide](./12-normalising-and-shipping-with-bower.md)) in SOWs as an open-source reference normaliser and Australian privacy gateway, so vendors do not charge bespoke engineering fees to build host-side TFN/Medicare/IHI redaction, default-deny noise filtering, tamper-evident queuing, legacy SQL Server/WEC adapters, or signed Sentinel arrival proof (`bower evidence run`).

---

## Acceptance Gate Checklist

Use [`templates/logging-acceptance-checklist.md`](../templates/logging-acceptance-checklist.md) as a formal UAT / Go-Live sign-off sheet signed jointly by the **Vendor Tech Lead** and the **Agency SOC / Security Lead**.
