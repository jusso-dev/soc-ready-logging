# Vendor Security Logging — Day-1 SOC Handoff Pack

> Complete this document before UAT sign-off / Authority to Operate (ATO), or generate a pre-filled version with `python3 scripts/generate_soc_handoff.py`.

---

## 1. Application Identity & Ownership

| Field | Value |
|---|---|
| **Application ID (`app.id`)** | `e.g. gov-grants-portal` |
| **Application Name (`app.name`)** | `e.g. Grants Management Portal` |
| **Data Classification (PSPF)** | `OFFICIAL` / `OFFICIAL:Sensitive` / `PROTECTED` |
| **Environments Emitting to SIEM** | `prod`, `uat` |
| **Hosting Platform** | `e.g. Azure Kubernetes Service (Australia East)` |
| **Identity Provider (IdP)** | `e.g. Microsoft Entra ID (OIDC + FIDO2 MFA)` |
| **Vendor Security / Engineering Contact** | `Name, Email, On-Call Phone` |
| **Agency System Owner / SOC Lead** | `Name, Email` |

---

## 2. Log Transport, Integrity & Time Sync

- **Format**: Single-line UTF-8 JSON (NDJSON) conforming to `soc-ready-logging` schema `v1.0.0`.
- **Stream filter**: `stream == "security"` routed to SOC SIEM; `stream == "operational"` routed to APM / operational logs.
- **Transport mechanism**: `e.g. Bower Privacy Gateway (jusso-dev/Bower) -> Azure Monitor Logs Ingestion API (DCE/DCR) -> CustomAppSecurity_CL (or AMA spool / S3 / Splunk HEC)`
- **Host-side privacy & default-deny policy**: `e.g. Bower Privacy & Secret Protection Engine (AU TFN/Medicare/IHI/ABN/CRN + secrets) + signed Pack version vX.Y`
- **Tamper evidence & write-only isolation (ACSC ISM-1405 / ISM-1815)**: Application runtime credentials cannot query, modify, or delete ingested SIEM records (and Bower maintains a hash-chained SQLite WAL queue ledger).
- **Time synchronization (ACSC ISM-0988)**: All timestamps emitted in UTC ISO-8601 (`...Z`) from NTP-synced hosts.
- **Client IP preservation**: True client IP extracted from trusted gateway header (`e.g. X-Azure-ClientIP` / rightmost untrusted `X-Forwarded-For` behind WAF CIDR `x.x.x.x/24`).
- **Pipeline liveness heartbeat**: `sys_logging_heartbeat` emitted every `15` minutes per production service. Alert if silent > `90` minutes.

---

## 3. Expected Volume & Retention Sizing

| Environment | Expected Events / Day | Peak Events / Min | Avg Payload Size | Est. Monthly SIEM Volume |
|---|---:|---:|---:|---:|
| `prod` | `e.g. 12,000` | `e.g. 80` | `~900 bytes` | `~0.32 GB / month` |
| `uat` | `e.g. 1,500` | `e.g. 20` | `~900 bytes` | `~0.04 GB / month` |

---

## 4. Implemented Security Event Catalog

| Event (`event`) | Category | Default Severity | Priority | Trigger Condition |
|---|---|---|---|---|
| `authn_login_success` | `authentication` | `INFO` | P1 | Interactive login / OIDC callback completed |
| `authn_login_fail` | `authentication` | `WARN` | P1 | Failed credential / token validation |
| `authn_login_success_after_fail` | `authentication` | `HIGH` | P1 | Login succeeded after >= 3 failures in 10 min |
| `authn_mfa_fail` | `authentication` | `WARN` | P1 | MFA challenge denied, expired, or invalid |
| `authn_mfa_disabled` | `authentication` | `CRITICAL` | P1 | MFA reset or disabled |
| `authz_fail` | `authorization` | `WARN` | P1 | Server-side HTTP 403 authorization denial |
| `priv_role_assigned` | `privilege` | `HIGH` | P1 | Role or privilege granted |
| `user_created` | `iam` | `WARN` | P1 | New account provisioned |
| `data_bulk_export` | `data_access` | `HIGH` | P1 | Export >= 50 sensitive records |
| `config_security_changed` | `configuration` | `HIGH` | P1 | Security policy / SSO / allowlist changed |
| `crypto_verification_fail` | `cryptography` | `HIGH` | P1 | Invalid JWT / SAML / webhook HMAC signature |
| `sys_logging_heartbeat` | `system` | `INFO` | P2 | Every 15 min pipeline health proof |
| `tamper_logging_disabled_or_cleared` | `tamper` | `CRITICAL` | P1 | Attempt to disable or clear audit logging |

---

## 5. Known Benign Baselines & Service Accounts (False-Positive Prevention)

List legitimate automation so SOC analysts do not chase expected traffic on Day 1:

| Actor ID / IP | Purpose | Expected Events | Schedule / Notes |
|---|---|---|---|
| `svc-nightly-reconcile` | Authorised finance export | `data_bulk_export` (~200 rows) | 02:00 AEST daily from `10.20.4.15` |
| `svc-scim-sync` | Entra ID SCIM provisioning | `user_created`, `user_disabled` | Continuous from Entra SCIM range |

---

## 6. Verification Evidence Attached

- [ ] Golden sample NDJSON (`valid-events.ndjson`) covering every implemented event
- [ ] `scripts/validate_logs.py --strict` pass report (0 schema, 0 secret/PII, 0 CWE-117 findings)
- [ ] `scripts/score_signal_noise.py` report (score `>= 90/100`, 0% debug/health noise)
- [ ] Live UAT SIEM ingestion & starter detection screenshot (`generate_test_events.py --scenario all`)
- [ ] Starter detection rules adapted (Sigma / Microsoft Sentinel KQL / Splunk SPL)
