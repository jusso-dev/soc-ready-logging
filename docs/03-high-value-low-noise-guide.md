# 03 — High-Value, Low-Noise Logging Guide

The single biggest gift a software vendor can give a Government SOC is **signal discipline**.

A SIEM is not a `console.log` dumping ground. Every megabyte sent to the SIEM costs real taxpayer money to ingest, parse, index, alert on, and retain for 12+ months. More importantly, **noise destroys analyst trust**—when a custom app floods the SIEM with meaningless `INFO` or `WARN` messages, analysts tune out the source and miss the real intrusion.

---

## The Two-Stream Architecture

Always separate logs into **two explicit streams** at the application boundary:

1. **Stream A — Security Audit Stream (`stream: "security"`) -> SOC SIEM**
   - Low volume, high signal, strict JSON schema (`schemas/security-event.schema.json`).
   - Never dropped by log-level changes or aggressive APM sampling.
   - Shipped out-of-process to the centralised SIEM (Sentinel, Splunk, Elastic, Chronicle) with tamper protection and 12+ month retention.
2. **Stream B — Operational & Debug Telemetry (`stream: "operational"`) -> APM / Data Lake**
   - Health checks, latency metrics, SQL debug traces, stack traces, background job heartbeats, feature flag checks.
   - Sampled, rotated, and kept on cheaper operational storage (7–30 days), **never routed to SIEM analytics tables**.

See the visual diagram in [`diagrams/architecture-two-stream.png`](../diagrams/architecture-two-stream.png).

---

## The Signal vs. Noise Decision Matrix

Before adding an event to `stream: "security"`, ask one question:

> *"Could a SOC analyst write a detection rule, hunt query, or forensic timeline step using this event?"*

If the answer is **no**, route it to operational telemetry instead.

### Always Log to SIEM (High Value, Low Noise)

- **Authentication state transitions**: login success/fail, login success after failures, account lockout, MFA challenge/failure/disablement, password reset, token revocation.
- **Authorization & privilege boundaries**: server-side HTTP 403 denials (`authz_fail`), role/privilege grants or revocations (`priv_role_assigned`), admin state changes (`authz_admin_action`), user impersonation (`authz_impersonation_start`).
- **Identity & credential lifecycle**: user create/disable/delete, API key or OAuth client creation/revocation.
- **Sensitive data boundaries**: bulk exports (`data_bulk_export`), deletion of sensitive records (`data_sensitive_deleted`), reads of explicitly classified records (`OFFICIAL:Sensitive`, `PROTECTED`) where required by agency policy.
- **Security controls & crypto integrity**: JWT/SAML/HMAC signature verification failures (`crypto_verification_fail`), security config changes (`config_security_changed`), high-confidence attack blocks (`input_validation_attack_suspected`).
- **Tamper & liveness**: audit config tampering (`tamper_logging_disabled_or_cleared`) and a low-frequency pipeline heartbeat (`sys_logging_heartbeat` every 15–60 min).

### Never Send to SIEM (High Noise, Low Security Value)

- **Health & readiness probes**: `/healthz`, `/readyz`, `/livez`, `/metrics`, load balancer pings.
- **Static & UI assets**: `.js`, `.css`, `.png`, `.svg`, `.woff2`, `favicon.ico`, manifest fetches.
- **Per-request token validation successes**: Do **not** emit `authn_login_success` on every API call that carries a valid JWT! Log authentication at **login / token issuance / refresh**, not 400 times per minute per browser tab.
- **UI feature-flag or menu visibility checks**: Only emit `authz_fail` when a principal actually attempts an unauthorized server-side action (HTTP 403).
- **Routine user form typos**: Missing `@` in an email field or blank required textbox is UX validation, not an attack. Only emit `input_validation_attack_suspected` when a real security control triggers (path traversal block, SSRF egress allowlist block, XML/deserialization rejection, WAF/sanitizer hit).
- **`DEBUG` / `TRACE` logs & SQL query dumps**: Keep exclusively in operational telemetry.
- **Raw 50-line stack traces**: Emit a concise `message` + `reason` + `correlation_id` to the security stream, and link via `correlation_id` to the full stack trace in APM if needed.

---

## Volume Control & Flood Protection

Even legitimate security events can become noisy during an attack or misconfiguration. Apply these three vendor-side safeguards:

1. **State-transition emission**: Emit `authn_login_lockout` when the account *enters* lockout—not on every subsequent blocked attempt while locked.
2. **Windowed suppression for floods**: For `api_rate_limit_exceeded`, emit one event per `(actor_or_ip, route, window)` with `details.suppressed_count` rather than 50,000 events during a 60-second credential stuffing burst.
3. **Never sample away `P1` events**: Never apply random probabilistic sampling (e.g., "keep 10%") to `stream: "security"`. Control volume by **choosing the right events** and **summarizing floods**, not by randomly dropping an attacker's privilege escalation event!

---

## Automated Noise Budgeting in CI

Use [`scripts/score_signal_noise.py`](../scripts/score_signal_noise.py) against staging/load-test log captures before every release. Target:

- **Signal-to-Noise Score**: `>= 90 / 100`
- **Health/static/debug contamination**: `0%`
- **Schema compliance**: `100%`
- **Unredacted secrets or PII**: `0`
- **P95 event payload size**: `< 2 KB` per event
