---
name: soc-handoff-pack
description: Generate a Day-1 Government SOC Handoff Pack, implemented Event Catalog, golden sample NDJSON, and tailored starter SIEM detections (Microsoft Sentinel KQL, Sigma, Splunk SPL) directly from a vendor codebase.
---

# Day-1 Government SOC Handoff Pack Generator

Use this skill once security logging is implemented and verified, to deliver everything a Government or Enterprise SOC needs to onboard, parse, baseline, and alert on the application on Day 1.

## Workflow

1. **Discover real implemented events & app metadata from the repository**
   - Extract exact `app.id`, `app.name`, deployed environments (`prod`, `uat`), hosting platform, IdP, transport mechanism (stdout/OTel/Fluent Bit/Azure Monitor DCR), trusted-proxy client IP header, and heartbeat interval.
   - Inventory every canonical `event` name actually emitted by the codebase (do not claim events that are not implemented).
   - Identify service accounts, scheduled jobs, and legitimate bulk exports so the SOC avoids Day-1 false positives.

2. **Generate the Handoff Pack**
   - If `generate_soc_handoff.py` is available, bootstrap with:
     ```bash
     python3 /path/to/soc-ready-logging/scripts/generate_soc_handoff.py \
       --app-id <app-id> \
       --app-name "<App Name>" \
       --classification "OFFICIAL:Sensitive" \
       --siem "Microsoft Sentinel" \
       --from-repo . \
       --out docs/SOC-HANDOFF-PACK.md
     ```
   - Enrich the generated document using [`references/handoff-structure.md`](./references/handoff-structure.md) with real transport details, estimated event volumes, service-account baselines, and vendor escalation contacts.

3. **Generate golden sample NDJSON & tailored starter detections**
   - Export or save `docs/soc-golden-events.ndjson` containing at least one schema-valid example for every implemented event (validated with `validate_logs.py --strict`).
   - Provide starter queries tailored to the app's exact `app.id` and target SIEM (Microsoft Sentinel KQL, Sigma, and/or Splunk SPL) covering:
     - Brute force followed by success
     - Authz/IDOR 403 bursts
     - Privilege escalation / MFA disablement / impersonation
     - Sensitive bulk data export
     - Silent pipeline dropout (`sys_logging_heartbeat` absence > 90m)

4. **Attach verification evidence**
   - Include the `validate_logs.py --strict` pass summary and `score_signal_noise.py` scorecard so IRAP assessors and SOC leads can sign off immediately.
