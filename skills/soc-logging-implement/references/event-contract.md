# Canonical Security Event Contract (`v1.0.0`)

## Required Top-Level Fields
- `schema_version`: `"1.0.0"`
- `timestamp`: UTC ISO-8601 ending in `Z` (e.g., `"2026-11-21T06:15:00.011Z"`)
- `stream`: `"security"`
- `event`: OWASP-prefixed lowercase snake_case (`^(authn|authz|session|user|priv|data|sys|config|input|api|crypto|tamper)_[a-z0-9_]+$`)
- `severity`: `"INFO"` | `"WARN"` | `"HIGH"` | `"CRITICAL"` (NEVER `DEBUG` or `TRACE`)
- `outcome`: `"success"` | `"failure"` | `"blocked"` | `"unknown"`
- `app`: `{ id, name, environment ("prod"|"staging"|"uat"|"test"|"dev"), version, component?, host? }`
- `actor`: `{ type ("user"|"admin"|"service"|"api_client"|"anonymous"|"system"), id, username?, roles?, tenant_id?, session_id_hash?, impersonated_by? }`
- `source`: `{ ip, port?, user_agent?, asn?, geo_country? }`
- `correlation_id`: 8–128 safe chars (`[A-Za-z0-9._:-]`)
- `message`: concise single-line human summary (4–512 chars)

## Optional High-Value Context
- `category`: `"authentication"|"authorization"|"session"|"iam"|"privilege"|"data_access"|"system"|"configuration"|"input_validation"|"api"|"cryptography"|"tamper"`
- `target`: `{ type?, id?, name?, classification? ("UNOFFICIAL"|"OFFICIAL"|"OFFICIAL:Sensitive"|"PROTECTED"|"PUBLIC"|"INTERNAL"|"CONFIDENTIAL"|"RESTRICTED") }`
- `http`: `{ method?, route? (parameterized e.g. "/api/v1/cases/{id}"), status_code? }`
- `reason`: short snake_case reason code (`invalid_credentials`, `missing_role`, `mfa_user_denied`, `invalid_signature`)
- `details`: bounded flat/shallow object (max 25 keys, never unredacted secrets/PII)

## Core P1 Events
`authn_login_success`, `authn_login_fail`, `authn_login_success_after_fail`, `authn_login_lockout`, `authn_mfa_success`, `authn_mfa_fail`, `authn_mfa_disabled`, `authn_password_changed`, `session_anomaly_detected`, `authz_fail`, `authz_admin_action`, `authz_impersonation_start`, `user_created`, `user_disabled`, `user_deleted`, `priv_role_assigned`, `priv_role_revoked`, `api_key_created`, `data_bulk_export`, `data_sensitive_deleted`, `config_security_changed`, `crypto_verification_fail`, `tamper_logging_disabled_or_cleared`, `sys_logging_heartbeat`.
