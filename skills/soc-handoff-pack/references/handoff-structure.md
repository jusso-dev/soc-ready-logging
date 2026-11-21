# Required Sections for `docs/SOC-HANDOFF-PACK.md`

1. **Application Identity & Contacts**: `app.id`, `app.name`, PSPF/data classification, environments (`prod`, `uat`), hosting region/platform, IdP, vendor security contact, agency owner.
2. **Transport, Integrity & Time Sync**: NDJSON over `stream == "security"`, collector/SIEM route, write-only isolation proof (ISM-1405 / ISM-1815), UTC NTP sync (ISM-0988), trusted-proxy IP header, `sys_logging_heartbeat` cadence.
3. **Volume & Cost Sizing**: Expected events/day, peak events/min, average & P95 payload bytes, estimated monthly GB for 12+ month searchable retention (ISM-1988).
4. **Implemented Event Catalog**: Table listing ONLY events actually emitted in code, with category, default severity, SIEM priority (P1/P2), trigger condition, MITRE ATT&CK ID, and ACSC ISM reference.
5. **Known Benign Baselines & Service Accounts**: Automated jobs, SCIM sync accounts, scheduled reports, and known internal IPs to suppress Day-1 false positives.
6. **Tailored Starter Detections**: Copy-paste SIEM queries bound to the app's exact `app.id` (Sentinel KQL, Sigma, or Splunk SPL).
7. **Verification Evidence**: `validate_logs.py --strict` pass output, `score_signal_noise.py` scorecard (`>= 90/100`), and link to `docs/soc-golden-events.ndjson`.
