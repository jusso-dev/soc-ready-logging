# Starter SOC Detection Rules

Because every vendor adopting `soc-ready-logging` emits the exact same canonical JSON fields and OWASP-prefixed event names, SOC teams can deploy **Day-1 detections immediately** without spending weeks writing fragile regex parsers.

## Included Detection Packs

| Format | Path | Target Platform |
|---|---|---|
| **Sigma** (vendor-neutral) | [`sigma/`](./sigma/) | Convert to any SIEM via `sigma-cli` |
| **Microsoft Sentinel KQL** | [`sentinel-kql/soc-starter-detections.kql`](./sentinel-kql/soc-starter-detections.kql) | Microsoft Sentinel / Azure Log Analytics (common in AU Gov) |
| **Splunk SPL** | [`splunk-spl/soc-starter-detections.spl`](./splunk-spl/soc-starter-detections.spl) | Splunk Enterprise Security |
| **Google SecOps YARA-L** | [`chronicle-yaral/soc-starter-detections.yaral`](./chronicle-yaral/soc-starter-detections.yaral) | Google Security Operations (Chronicle SIEM / UDM) |

## Day-1 Detections Covered

1. **Brute-Force / Password Spray Followed by Successful Login** (`authn_login_fail` -> `authn_login_success` / `authn_login_success_after_fail`): MITRE `T1110`, `T1078`
2. **Authorisation / IDOR Probing & Unauthorised Privilege Escalation** (`authz_fail` bursts, `priv_role_assigned`, `authz_impersonation_start`): MITRE `T1098`, `T1134`, `T1213`
3. **MFA Fatigue or MFA Disablement** (`authn_mfa_fail` bursts, `authn_mfa_disabled`): MITRE `T1621`, `T1556.006`
4. **Anomalous Bulk Export of Sensitive Government Data** (`data_bulk_export` on `OFFICIAL:Sensitive` / `PROTECTED`): MITRE `T1530`
5. **Audit Trail Tampering or Silent Pipeline Dropout** (`tamper_logging_disabled_or_cleared` + `sys_logging_heartbeat` absence): MITRE `T1562.008`, `T1070`
6. **Cryptographic / Token Signature Tampering** (`crypto_verification_fail` with `reason == "invalid_signature"`): MITRE `T1550`, `T1606`
