---
name: soc-logging-implement
description: Implement high-value, low-noise, two-stream OWASP and ACSC ISM aligned security logging in a custom application (TypeScript/Node, Python, C#/.NET, Go, or Java) with minimal boilerplate, automatic secret/PII redaction, and CWE-117 log injection safety.
---

# SOC Logging Implementation

Use this skill to implement or refactor an application's security logging so a Government or Enterprise SOC can ingest and alert on it immediately with near-zero noise.

## Rules Before Writing Code

1. **Enforce strict two-stream separation**:
   - Create a dedicated `SecurityLogger` wrapper that emits single-line UTF-8 JSON (NDJSON) with `"stream": "security"`.
   - Leave debug, trace, health-check, latency, and SQL logs on the existing operational logger (`"stream": "operational"` or separate sink). Never upgrade debug logs into security events.
2. **Follow the canonical event contract** in [`references/event-contract.md`](./references/event-contract.md):
   - Always populate: `schema_version` (`"1.0.0"`), `timestamp` (UTC ISO-8601 `Z`), `stream` (`"security"`), `event` (OWASP prefix), `severity` (`INFO`|`WARN`|`HIGH`|`CRITICAL` — never `DEBUG`), `outcome` (`success`|`failure`|`blocked`|`unknown`), `app`, `actor`, `source`, `correlation_id`, `message`.
3. **Bake safety into the wrapper itself**:
   - Automatically redact keys matching `password|secret|token|authorization|cookie|api_key|private_key|tfn|medicare|ssn|credit_card|cvv|pin|otp` -> `"[REDACTED]"`.
   - Regex-scrub Bearer tokens, JWTs (`eyJ...`), and PEM private key blocks inside string values.
   - Strip ASCII control chars (`\x00-\x1f`, `\x7f`) and ANSI escape sequences before JSON encoding (CWE-117).
   - Provide `hashSessionId(raw, salt)` returning `sha256:<32 hex chars>` so raw session tokens are never logged.
4. **Preserve true client IP & correlation ID**:
   - Wire request middleware to propagate incoming W3C `traceparent` / `X-Correlation-Id` (or generate a UUID).
   - Extract true client IP only from configured trusted proxy CIDRs—never blindly trust spoofable `X-Forwarded-For` from untrusted callers.
5. **Wire only high-value security boundaries (low noise)**:
   - Authn transitions (login success/fail, success-after-fail, lockout, MFA success/fail/disabled, password change, token revoke) — **never** on every authenticated HTTP request.
   - Server-side authorization denials (HTTP 403 -> `authz_fail`), role/privilege changes (`priv_role_assigned`, `priv_role_revoked`), admin actions & impersonation.
   - User lifecycle (`user_created`, `user_disabled`, `user_deleted`), API key create/revoke, rate-limit window summaries (`api_rate_limit_exceeded`).
   - Sensitive bulk exports (`data_bulk_export`), sensitive deletes (`data_sensitive_deleted`), security config changes (`config_security_changed`), and signature verification failures (`crypto_verification_fail`).
   - Periodic low-frequency pipeline heartbeat (`sys_logging_heartbeat`, default every 15–60 min) and `tamper_logging_disabled_or_cleared`.
6. **Keep errors safe for end users (OWASP ASVS V16.5)**:
   - Return generic error JSON with `correlation_id` to callers; never leak stack traces or SQL errors.

## Implementation Steps

1. Add the minimal `SecurityLogger` module tailored to the repo's language and DI/framework conventions (no unnecessary third-party dependencies).
2. Add or update request-context middleware for `correlation_id` and trusted-proxy `source.ip`.
3. Instrument P1 security boundaries cleanly using the wrapper.
4. Configure the cloud-appropriate collector/router filter (`stream == "security"`) if deployment/IaC manifests exist in the repo:
   - **Azure**: DCR KQL transform (`where stream == "security"`), Managed Identity with write-only `Monitoring Metrics Publisher`, `X-Azure-ClientIP` behind Front Door (`docs/08-azure-logging-guide.md`).
   - **AWS**: CloudWatch Subscription Filter (`{ $.stream = "security" }`) or FireLens `rewrite_tag` -> Firehose -> isolated Log Archive account S3 Object Lock / Security Lake (`docs/09-aws-logging-guide.md`).
   - **GCP**: Cloud Logging Router Sink (`jsonPayload.stream="security"`) -> Pub/Sub + Locked Log Bucket -> Google SecOps (`docs/10-gcp-logging-guide.md`).
   - **Cross-Cloud / Hybrid**: Always filter before egress and authenticate via OIDC / Workload Identity Federation (zero static IAM/SA keys — `docs/11-cross-cloud-log-federation.md`).
5. Hand off to `soc-logging-verify` to run automated schema, redaction, injection, and signal-to-noise tests.
