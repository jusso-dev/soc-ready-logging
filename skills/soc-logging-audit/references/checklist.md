# SOC Logging Audit Rubric

## 1. P1 Security Boundaries to Locate
- Login / OIDC callback / SAML ACS / token issuance -> `authn_login_success`, `authn_login_fail`, `authn_login_success_after_fail`, `authn_login_lockout`
- MFA verify / enroll / reset / disable -> `authn_mfa_success`, `authn_mfa_fail`, `authn_mfa_disabled`
- Password change / reset & token revoke -> `authn_password_changed`, `authn_token_revoked`
- Authorization middleware / HTTP 403 handler -> `authz_fail`
- Admin routes & user impersonation -> `authz_admin_action`, `authz_impersonation_start`
- User & role lifecycle -> `user_created`, `user_disabled`, `user_deleted`, `priv_role_assigned`, `priv_role_revoked`
- API keys / OAuth secrets / rate limiters -> `api_key_created`, `api_key_revoked`, `api_rate_limit_exceeded` (window-summarized)
- Sensitive data export / deletion -> `data_bulk_export`, `data_sensitive_deleted`
- Security config updates (SSO, CORS, IP allowlist, webhooks) -> `config_security_changed`
- JWT / SAML / HMAC / mTLS signature failures -> `crypto_verification_fail`
- Pipeline health & tamper protection -> `sys_logging_heartbeat`, `tamper_logging_disabled_or_cleared`

## 2. Red-Flag Noise Patterns (Must NOT Enter SIEM)
- `/health`, `/healthz`, `/readyz`, `/livez`, `/metrics`
- `.js`, `.css`, `.png`, `.svg`, `.woff2`, `favicon.ico`
- `DEBUG` / `TRACE` log levels or ORM SQL query dumps
- Emitting `authn_login_success` on every authenticated API request (emit at login/token issuance only)
- Emitting `input_validation_attack_suspected` on ordinary form typos (emit only on security control blocks)

## 3. Red-Flag Safety Hazards (Must Be Zero)
- Logging `password`, `passwd`, `secret`, `authorization`, `bearer`, `cookie`, `jwt`, `api_key`, `private_key`, `req.body`, `req.headers`
- Logging Australian TFN, Medicare number, passport, driver licence, or payment card numbers
- Building log lines with string concatenation/interpolation of untrusted headers (`User-Agent`, `X-Forwarded-For`, `username`) without JSON encoding and control-char stripping (CWE-117)
- Local timestamps instead of UTC ISO-8601 (`...Z`)
- Returning raw stack traces or SQL errors to clients (ASVS V7.4 / V16.5)
