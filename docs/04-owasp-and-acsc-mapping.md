# 04 — OWASP & ACSC (ASD) Standards Traceability Matrix

Government agencies and IRAP assessors rarely accept "we use a logging library" as compliance evidence. They need clear traceability between **what your application emits** and the exact **ACSC ISM** and **OWASP** requirements.

> **Important note on ISM versions**: The Australian Signals Directorate (ASD) updates the Information Security Manual (ISM) quarterly, occasionally revising control wording or rescinding legacy IDs (for example, legacy retention control `ISM-0859` was rescinded and superseded by `ISM-1988`/`ISM-1989`). Always cross-check control identifiers against the live ISM release on [cyber.gov.au/ism](https://www.cyber.gov.au/ism) (or via tools like [ISMSearch](https://github.com/jusso-dev/ISMSearch)).

---

## 1. ACSC Information Security Manual (ISM) — Guidelines for System Monitoring

| ACSC ISM Area / Control | Requirement Summary | How `soc-ready-logging` Satisfies It |
|---|---|---|
| **Event Logging Policy (`ISM-0580`)** | Maintain an event logging policy defining events to log, facilities used, monitoring procedures, and retention. | Vendor delivers [`templates/soc-handoff-pack.md`](../templates/soc-handoff-pack.md) + `schemas/event-catalog.json` documenting exact scope, ownership, and baselines. |
| **Event Log Details (`ISM-0585`)** | Every event records date/time, user/process, filename/resource (if applicable), event description, and ICT equipment involved. | Enforced by `schemas/security-event.schema.json`: `timestamp`, `actor.id`, `target.id`/`target.name`, `message`, `app.host`/`app.id`. |
| **Accurate & Consistent Time (`ISM-0988`)** | Accurate, consistent time source used across systems for event logging. | Mandatory UTC ISO-8601 (`...Z`) validated by `scripts/validate_logs.py`; NTP/time-sync verified in SOC handoff pack. |
| **Centralised Event Logging (`ISM-1405`)** | Implement a centralised event logging facility (SIEM) to capture and manage logs centrally. | Two-stream architecture routes `stream: "security"` out-of-process to central SIEM (Sentinel, Splunk, Elastic) via OTel/Fluent Bit/DCR or custom collectors. |
| **Log Protection (`ISM-1815` / System Monitoring protection controls)** | Protect event logs from unauthorised access, modification, or deletion. | Append-only out-of-process shipping, no local-only audit logs, `tamper_logging_disabled_or_cleared` event, plus `sys_logging_heartbeat` to detect silent drops. |
| **Timely Cyber Security Event Analysis (`ISM-1228`)** | Analyse cyber security events in a timely manner to identify cyber security incidents. | Deterministic OWASP event names + Day-1 starter detections (`detections/sigma`, `detections/sentinel-kql`, `detections/splunk-spl`) enable immediate automated alerting. |
| **Searchable Log Retention (`ISM-1988` / NAA AFDA Express)** | Retain event logs in a searchable manner for at least 12 months (or longer per National Archives / agency obligations). | Low-noise, compact (<2 KB) JSON design makes 12+ month hot/searchable SIEM retention financially sustainable. |

---

## 2. ACSC Practitioner Guidance Alignment

- **ACSC *Best Practices for Event Logging and Threat Detection*** (joint ASD/ACSC, CISA, NCSC, CSE, NCSC-NZ guidance):
  - Prioritises **high-value security events** (logins, privilege changes, configuration changes, tamper attempts) over indiscriminate logging.
  - Emphasises **structured, normalised, UTC-timestamped** output shipped to hardened, segmented logging infrastructure.
- **ACSC *Priority Logs for SIEM Ingestion: Practitioner Guidance***:
  - Explicitly advises **not** dumping raw operational application text logs directly into the SIEM.
  - Recommends splitting operational/debugging logs into cheaper storage while forwarding **parsed, high-value security events** into the SIEM with gradual, validated onboarding.
- **ACSC Essential Eight Context**:
  - **Multi-Factor Authentication (MFA)**: Capturing `authn_mfa_success`, `authn_mfa_fail`, `authn_mfa_disabled`, and `details.mfa_method` (e.g., `fido2`, `webauthn`) proves phishing-resistant MFA enforcement and detects MFA fatigue/downgrades.
  - **Restrict Administrative Privileges**: Capturing `priv_role_assigned`, `priv_role_revoked`, `authz_admin_action`, and `authz_impersonation_start` gives direct visibility into privileged account use and misuse.

---

## 3. OWASP Standards Alignment

| OWASP Standard | Specific Guidance / Chapter | Implementation in This Repo |
|---|---|---|
| **OWASP Logging Cheat Sheet** | Log authn/authz/input/admin events; never log credentials, tokens, or unnecessary PII; prevent log injection; centralize tamper-resistant logs. | Full coverage across `docs/02`–`05`, `examples/` reference loggers, and automated checks in `scripts/validate_logs.py`. |
| **OWASP Application Logging Vocabulary Cheat Sheet** | Standardized event prefixes (`authn_*`, `authz_*`, `user_*`, `sys_*`, `input_*`, etc.) in structured JSON. | `schemas/event-catalog.json` adopts OWASP prefix conventions and maps each canonical event to `compliance.owasp_event`. |
| **OWASP ASVS v4.0.3 (Chapter V7)** | **V7.1** Log Content (no secrets/PII, sufficient context); **V7.2** Log Processing (SIEM-consumable); **V7.3** Log Protection (tamper resistance); **V7.4** Error Handling (safe client errors). | Automated PII/secret & CWE-117 checks in `validate_logs.py`; generic error guidance in `docs/05`. |
| **OWASP ASVS v5.0 (Chapter V16)** | **V16.3** Centralized Security Logging (authn, factor metadata, crypto/TLS/signature/authz failures); **V16.4** Log Protection & Integrity; **V16.5** Safe Error Handling. | Includes `crypto_verification_fail`, `authn_mfa_*`, `tamper_logging_disabled_or_cleared`, and `sys_logging_heartbeat`. |
| **OWASP Top 10 — A09: Security Logging and Monitoring Failures** | Prevents blind spots where breaches go undetected due to missing audit events, unmonitored logs, or local-only storage. | Closes the loop from vendor code -> CI schema gate -> Day-1 SOC SIEM detections. |

---

## Using This Matrix in IRAP & Security Assessments

When preparing a System Security Plan (SSP) or IRAP evidence pack:

1. Attach your application's generated **SOC Handoff Pack** (`scripts/generate_soc_handoff.py`).
2. Attach the latest CI pass report from `scripts/validate_logs.py --strict` and `scripts/score_signal_noise.py`.
3. **Generate signed Sentinel proof of arrival with [Bower](https://github.com/jusso-dev/Bower)** (`bower evidence run`) — Bower sends a canary through the real collector, verifies it inside Microsoft Sentinel with a read-only KQL query, records latency, retention, and Australian region, maps the results to **ACSC ISM & Essential Eight** controls, and signs the evidence bundle (see [`12-normalising-and-shipping-with-bower.md`](./12-normalising-and-shipping-with-bower.md)).
4. Include a screenshot/export of a synthetic attack test (`scripts/generate_test_events.py --scenario brute-force-takeover`) triggering a SOC alert.
