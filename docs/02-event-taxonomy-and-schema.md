# 02: Canonical Event Taxonomy & Schema

This guide defines the **canonical SOC-ready security event contract** codified in [`schemas/security-event.schema.json`](../schemas/security-event.schema.json) and [`schemas/event-catalog.json`](../schemas/event-catalog.json).

The schema is deliberately compact so custom software vendors can implement it in a few hours, while giving Government SOCs every field required for **ACSC ISM-0585**, **OWASP Logging Vocabulary**, **Microsoft Sentinel**, **Splunk**, **Elastic (ECS)**, and **OCSF** normalisation.

---

## Mandatory Top-Level Fields

Every security event MUST be emitted as **one JSON object per line (NDJSON)** with these 11 required top-level fields:

| Field | Type | Requirement | Why the SOC needs it |
|---|---|---|---|
| `schema_version` | `"1.0.0"` | Required | Allows non-breaking SIEM parser upgrades |
| `timestamp` | UTC ISO-8601 (`...Z`) | Required | Cross-system forensic timeline correlation (ISM-0988) |
| `stream` | `"security"` | Required | Clean routing filter separating SIEM events from debug logs |
| `event` | OWASP prefix name | Required | Deterministic detection rules (never parse free-text messages) |
| `severity` | `INFO` \| `WARN` \| `HIGH` \| `CRITICAL` | Required | Triage prioritisation (`DEBUG`/`TRACE` forbidden here) |
| `outcome` | `success` \| `failure` \| `blocked` \| `unknown` | Required | Instantly distinguishes attempted vs. succeeded attacks |
| `app` | Object (`id`, `name`, `environment`, `version`, `host`) | Required | Identifies exact system, environment (`prod` vs `uat`), and host (ISM-0585) |
| `actor` | Object (`type`, `id`, optional `roles`, `tenant_id`, `session_id_hash`) | Required | Immutable principal identity (Entra OID, UUID, service principal) |
| `source` | Object (`ip`, optional `user_agent`, `geo_country`) | Required | True client IP for threat-intel matching & geo/ASN correlation |
| `correlation_id` | Trace/request ID | Required | Joins WAF, API gateway, app, and database logs |
| `message` | Single-line string | Required | Concise human-readable summary for L1 SOC analysts (ISM-0585) |

### Strongly Recommended Contextual Objects

- `target`: `{ type, id, name, classification }`: Essential for `authz_fail`, `user_*`, `priv_*`, `data_*`, and `config_*` events. Supports Australian PSPF markings (`UNOFFICIAL`, `OFFICIAL`, `OFFICIAL:Sensitive`, `PROTECTED`) and enterprise labels.
- `http`: `{ method, route, status_code }`: Use **parameterised routes** (`/api/v1/cases/{id}`), never raw URLs with query tokens.
- `reason`: Short machine-readable snake_case code (e.g., `invalid_credentials`, `mfa_user_denied`, `missing_role`, `invalid_signature`).
- `details`: Bounded key-value object (max 25 keys) for event-specific attributes (`failed_attempts`, `record_count`, `role_name`, `mfa_method`, `changed_fields`).
- `compliance`: Optional tags (`owasp_event`, `mitre_attack`, `ism_controls`) to simplify governance reporting.

---

## OWASP-Aligned Event Prefix Taxonomy

Event names follow `<domain>_<action>` in lowercase snake_case, directly aligned with the **OWASP Application Logging Vocabulary Cheat Sheet**:

| Prefix | Domain | High-Value Events | Typical SIEM Priority |
|---|---|---|---|
| `authn_*` | Authentication | `authn_login_success`, `authn_login_fail`, `authn_login_success_after_fail`, `authn_login_lockout`, `authn_mfa_success`, `authn_mfa_fail`, `authn_mfa_disabled`, `authn_password_changed`, `authn_token_revoked`, `authn_logout` | **P1** |
| `session_*` | Session security | `session_anomaly_detected` (token replay, binding mismatch) | **P1** |
| `authz_*` | Authorisation | `authz_fail`, `authz_admin_action`, `authz_impersonation_start` | **P1** |
| `user_*` | User lifecycle (IAM) | `user_created`, `user_updated`, `user_disabled`, `user_deleted` | **P1** |
| `priv_*` | Privilege changes | `priv_role_assigned`, `priv_role_revoked` | **P1** |
| `api_*` | API & credential security | `api_key_created`, `api_key_revoked`, `api_rate_limit_exceeded` | **P1 / P2** |
| `data_*` | Sensitive data access | `data_sensitive_read`, `data_bulk_export`, `data_sensitive_deleted` | **P1 / P2** |
| `config_*` | Security configuration | `config_security_changed` | **P1** |
| `input_*` | High-confidence attack blocks | `input_validation_attack_suspected` | **P2** |
| `crypto_*` | Cryptographic / token integrity | `crypto_verification_fail` | **P1** |
| `sys_*` | Service & pipeline health | `sys_startup`, `sys_logging_heartbeat` | **P2** |
| `tamper_*` | Audit trail tampering | `tamper_logging_disabled_or_cleared` | **P1 (CRITICAL)** |

See [`schemas/event-catalog.json`](../schemas/event-catalog.json) for all 32 events with required `details` keys, noise controls, MITRE ATT&CK IDs, OWASP ASVS refs, and ACSC ISM references.

---

## Crosswalk to ECS, OCSF, and Microsoft Sentinel (ASIM)

SOC teams rarely need vendors to emit massive nested ECS or OCSF payloads directly from business logic. Emitting our clean canonical schema lets the SIEM ingestion pipeline (Fluent Bit, OpenTelemetry Collector, Azure Monitor DCR, or Cribl) map fields 1:1 without loss:

| Canonical Field | Elastic Common Schema (ECS) | OCSF | Microsoft Sentinel (ASIM / Custom DCR) |
|---|---|---|---|
| `timestamp` | `@timestamp` | `time` | `TimeGenerated` |
| `event` | `event.action` | `activity_name` | `EventType` / `EventSubType` |
| `category` | `event.category` | `class_name` | `EventCategory` |
| `severity` | `log.level` | `severity` | `EventSeverity` |
| `outcome` | `event.outcome` | `status` | `EventResult` |
| `actor.id` | `user.id` | `actor.user.uid` | `ActorUserId` |
| `actor.username` | `user.name` | `actor.user.name` | `ActorUsername` |
| `source.ip` | `source.ip` | `src_endpoint.ip` | `SrcIpAddr` |
| `source.user_agent` | `user_agent.original` | `http_request.user_agent` | `HttpUserAgent` |
| `target.id` | `resource.id` | `dst_endpoint.uid` / `resources[].uid` | `TargetResourceId` |
| `http.method` | `http.request.method` | `http_request.http_method` | `HttpRequestMethod` |
| `http.route` | `url.path` | `http_request.url.path` | `Url` |
| `http.status_code` | `http.response.status_code` | `http_response.code` | `HttpStatusCode` |
| `correlation_id` | `trace.id` | `metadata.correlation_uid` | `TransactionId` |
| `app.id` | `service.name` | `metadata.product.name` | `EventProduct` |
| `app.host` | `host.name` | `device.hostname` | `DvcHostname` |

---

## Golden Example Event

```json
{
  "schema_version": "1.0.0",
  "timestamp": "2026-11-21T06:15:00.011Z",
  "stream": "security",
  "event": "priv_role_assigned",
  "category": "privilege",
  "severity": "HIGH",
  "outcome": "success",
  "app": {
    "id": "gov-grants-portal",
    "name": "Grants Management Portal",
    "component": "admin-api",
    "environment": "prod",
    "version": "2.14.3",
    "host": "grants-admin-01.prod.internal"
  },
  "actor": {
    "type": "admin",
    "id": "oid-admin-00112233",
    "roles": ["tenant_admin"],
    "tenant_id": "agency-01",
    "session_id_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb924"
  },
  "source": {
    "ip": "198.51.100.10",
    "geo_country": "AU"
  },
  "target": {
    "type": "user",
    "id": "oid-9f8e7d6c-1122-4455-8899-aabbccddeeff"
  },
  "http": {
    "method": "POST",
    "route": "/api/v1/admin/users/{id}/roles",
    "status_code": 200
  },
  "correlation_id": "trace-8bf92f3577b34da6a3ce929d0e0e4810",
  "message": "Assigned role grants_approver to user oid-9f8e7d6c-1122-4455-8899-aabbccddeeff",
  "details": {
    "role_name": "grants_approver",
    "ticket_ref": "CHG0042181"
  }
}
```
