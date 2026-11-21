# 05 — PII Redaction, Secret Scrubbing & Log Safety

Security logs must **never** become a secondary breach vector. In government environments governed by the **Privacy Act 1988 (Cth)**, the **Notifiable Data Breaches (NDB) scheme**, **PSPF**, and **OWASP ASVS V7/V16**, leaking secrets or regulated citizen data into a centrally retained SIEM can turn a routine audit into a reportable incident.

---

## 1. The Absolute Never-Log List

Never emit any of the following—in `message`, `details`, `http.route`, `target.name`, or stack traces:

- **Credentials & secrets**: Cleartext passwords, password hashes, PINs, OTP codes, MFA recovery codes, private keys (`-----BEGIN ... PRIVATE KEY-----`), database connection strings.
- **Session & bearer material**: Raw session IDs, cookies, `Authorization: Bearer ...` headers, JWTs (`eyJ...`), OAuth access/refresh tokens, SAML assertions, API keys, pre-signed S3/Blob URLs.
- **Government & financial identifiers**: Australian Tax File Numbers (TFNs), Medicare numbers, Passport / Driver Licence numbers, full credit card PANs / CVVs, BSB + bank account numbers.
- **Sensitive free-form payloads**: Raw HTTP request/response bodies, citizen medical/welfare narratives, uploaded document contents, full search queries that may contain PII.

### Safe Alternatives for Correlation

| Instead of logging... | Log this instead |
|---|---|
| Raw session cookie / JWT | `actor.session_id_hash`: `"sha256:<first-32-hex-chars-of-salted-hash>"` |
| API key secret | `details.key_id`: `"key_01J9..."` + `details.scopes` |
| Full URL with query tokens (`/reset?token=abc`) | Parameterized `http.route`: `"/api/v1/auth/reset"` |
| User's full form submission | `details.changed_fields`: `["email", "phone"]` |
| Citizen TFN or Medicare number | Internal opaque record UUID (`target.id: "rec-992104"`) + `target.classification: "OFFICIAL:Sensitive"` |

---

## 2. Defense-in-Depth Redaction

Do not rely on every developer remembering what to omit. Enforce redaction in **three layers**:

1. **Logger wrapper denylist + pattern scrubber** (see `examples/`):
   - Automatically replace values under sensitive keys (`password`, `passwd`, `secret`, `token`, `authorization`, `cookie`, `api_key`, `tfn`, `medicare`, `ssn`, `credit_card`, `cvv`, `private_key`) with `"[REDACTED]"`.
   - Regex-scrub accidental JWTs, Bearer tokens, PEM blocks, AWS/Azure/GitHub keys, and credit-card-like patterns even inside string fields.
2. **CI / pre-commit verification**:
   - Run `scripts/validate_logs.py --strict` against integration-test log captures.
   - Run `scripts/audit_repo_logging.py` on every pull request to catch unsafe logging calls before merge.
3. **Host-side privacy gateway / collector scrub (Recommended: [Bower](https://github.com/jusso-dev/Bower))**:
   - Deploy **[jusso-dev/Bower](https://github.com/jusso-dev/Bower)** (`Collect → Select → Arrange → Deliver → Prove`) as a self-hosted privacy gateway before logs leave the host or enter the SIEM. Bower runs a deterministic **Privacy & Secret Protection Engine** (no AI at runtime) with checksum-validated **TFN, Medicare, IHI, ABN/ACN, and payment cards**, pattern-matched **CRN** and cloud/JWT/PEM secrets, quarantining on any failure and emitting a first-class `sensitive_data_detected` alert to the SOC (without original values). See [`12-normalising-and-shipping-with-bower.md`](./12-normalising-and-shipping-with-bower.md).
   - If not using Bower, configure a secondary redaction filter in Fluent Bit / OpenTelemetry Collector / Sentinel DCR as a safety net (noting that DCR redaction runs *after* data leaves the host).

---

## 3. Preventing Log Injection / Log Forging (CWE-117)

Attackers routinely inject `\r`, `\n`, `\t`, or ANSI terminal escape sequences (`\x1b[...`) into `User-Agent`, `username`, or `Referer` headers to:
- Forge fake `authn_login_success` lines in plain-text logs
- Break NDJSON line framing
- Exploit terminal rendering when analysts inspect raw logs

**Mandatory mitigations** (implemented in all reference loggers in `examples/`):

1. **Always serialize with a real JSON encoder** — never concatenate strings to build JSON.
2. **Strip or replace ASCII control characters** (`0x00–0x1F`, `0x7F`) and ANSI escape sequences in every string field before emission.
3. **Enforce strict max lengths** on untrusted fields (`user_agent` <= 512 chars, `message` <= 512 chars, `details` <= 25 keys) to prevent log-flooding / memory exhaustion attacks.

---

## 4. Safe Error Handling (OWASP ASVS V7.4 / V16.5)

- **To the end user / API caller**: Return a generic, non-leaking error body containing **only** an opaque `correlation_id` (e.g., `{"error": "Access denied", "correlation_id": "trace-7af9..."}`). Never return stack traces, SQL errors, internal hostnames, or framework versions.
- **To the security stream**: Emit a structured event (`authz_fail`, `crypto_verification_fail`) with `correlation_id`, concise `reason`, and `message`.
- **To operational telemetry**: Record full exception details linked by the same `correlation_id` (still scrubbed of secrets).

---

## 5. Tamper Resistance & Time Integrity (ACSC ISM-0988, ISM-1405, ISM-1815)

- **UTC everywhere**: Format all timestamps in UTC ISO-8601 (`YYYY-MM-DDTHH:MM:SS.sssZ`). Hosts/containers must sync from authoritative NTP / cloud time sources.
- **Out-of-process shipping**: Application processes must never rely solely on local writable files that a compromised app container can `truncate` or `rm`. Emit `stream: "security"` to stdout/OTLP/syslog collected by an isolated sidecar or host agent with write-only SIEM credentials.
- **Fail-visible, not fail-silent**: Track dropped log counts and expose them in `sys_logging_heartbeat` (`details.dropped_events`). If an admin attempts to disable audit logging, emit `tamper_logging_disabled_or_cleared` at `CRITICAL`.
