# Required Security Logging Verification Scenarios

## Positive Contract Tests
1. `authn_login_fail` -> `severity: "WARN"`, `outcome: "failure"`, `reason: "invalid_credentials"`, UTC `timestamp` ending in `Z`, no password present.
2. `authn_login_success_after_fail` -> `severity: "HIGH"`, `details.failed_attempts >= 3`, `actor.session_id_hash` matches `^sha256:[a-f0-9]{16,64}$`.
3. `authz_fail` -> `severity: "WARN"`, `outcome: "blocked"`, `http.status_code: 403`, parameterised `http.route` (no query tokens), `target.id` populated.
4. `priv_role_assigned` -> `severity: "HIGH"`, `actor.id` (admin) distinct from `target.id` (recipient), `details.role_name` populated.
5. `data_bulk_export` -> `severity: "HIGH"`, `target.classification` set, `details.record_count` set.
6. `sys_logging_heartbeat` -> `actor.type: "system"`, `details.interval_seconds` & `details.dropped_events` set.

## Negative Safety Tests (MUST PASS)
1. **Password & Bearer JWT Redaction**: Pass `details: { password: "TestPassword123!", authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature12345" }` -> assert neither secret appears anywhere in the serialised output and sensitive keys equal `"[REDACTED]"`.
2. **Regulated PII Key Redaction**: Pass `details: { tfn: "123 456 789", medicare: "2123 45678 1" }` -> assert both are `"[REDACTED]"`.
3. **CWE-117 Log Injection**: Pass `username: "alice\n2026-11-21T00:00:00Z INFO authn_login_success admin"` and `user_agent: "Mozilla\x1b[31m\r\nInjected"` -> assert output contains `0` raw newlines (`len(output.splitlines()) == 1`) and `0` ANSI escape sequences.
4. **Noise Exclusion**: Call `/healthz` and static asset route -> assert `0` events emitted to `stream: "security"`.
