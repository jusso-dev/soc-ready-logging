# 06 — SOC Handoff & SIEM Onboarding Playbook

Good logging code is only half the job. A Government SOC cannot monitor what it hasn't onboarded, parsed, baselined, and alerted on. This playbook gives vendors and SOC engineers a clean, repeatable **Day-1 onboarding path**.

---

## 1. Recommended Transport Patterns

Pick the cleanest transport already supported by the agency's platform—avoid bespoke polling scripts unless the application is legacy and cannot push logs:

| Hosting Pattern | Recommended Transport | Notes |
|---|---|---|
| **Containers / Kubernetes / App Service** | Single-line JSON to `stdout` -> Fluent Bit / OpenTelemetry Collector -> SIEM | Filter on `stream == "security"` in the collector so operational logs route to APM/data lake while security logs route to SIEM. |
| **Azure / Microsoft Sentinel** | Azure Monitor Agent (AMA) / Logs Ingestion API + Data Collection Rule (DCR) -> Custom `_CL` table or ASIM parser | For legacy or custom apps that cannot integrate cleanly with Sentinel natively, see [`jusso-dev/Bower`](https://github.com/jusso-dev/Bower). |
| **AWS** | CloudWatch Logs / Kinesis Data Firehose (filtered on `{ $.stream = "security" }`) -> SIEM | Avoid shipping unfiltered `/aws/lambda` or ALB debug noise directly to SIEM. |
| **On-Prem / VM** | Local append-only JSON file or Unix socket -> Vector / Fluent Bit / Splunk Universal Forwarder / AMA over mTLS | Restrict file permissions (`0640`), rotate safely, never grant the app account delete permissions on remote SIEM sinks. |

---

## 2. True Client IP Behind Gateways & WAFs

Government apps almost always sit behind a WAF, Front Door, CloudFront, API Gateway, or reverse proxy. If your logger reads `req.socket.remoteAddress`, every security event will show `10.x.x.x`—making IP correlation impossible.

**Rule**:
- Configure an explicit list of **trusted proxy CIDRs**.
- Extract client IP from the trusted header (`X-Forwarded-For` rightmost untrusted hop, `True-Client-IP`, or `X-Azure-ClientIP`).
- Never blindly trust the first `X-Forwarded-For` value from an untrusted internet client (it is trivially spoofed!).

---

## 3. Pipeline Liveness: The Heartbeat Contract

The #1 silent failure in SIEM operations is a log pipeline breaking during an app upgrade, certificate expiry, or DCR change—leaving the SOC blind for months.

**Requirement**:
- Emit `sys_logging_heartbeat` once every **15–60 minutes** per production service.
- Include `details.interval_seconds`, `details.events_emitted_since_last`, and `details.dropped_events`.
- The SOC creates one simple **absence alert**: *"No `sys_logging_heartbeat` received from `app.id == 'gov-grants-portal'` (prod) in 90 minutes -> P3 Health Incident."*

---

## 4. The Day-1 SOC Handoff Pack

Before UAT sign-off / Authority to Operate (ATO), the vendor delivers four lightweight artefacts:

1. **Completed SOC Handoff Pack** ([`templates/soc-handoff-pack.md`](../templates/soc-handoff-pack.md), or generated with `scripts/generate_soc_handoff.py`):
   - App identity, environments, hosting, transport, expected events/day, and peak volume estimates.
   - Exact list of implemented events from `schemas/event-catalog.json`.
   - Service accounts, expected automation IPs, and known benign patterns (prevents false positives on Day 1!).
   - Incident response & vendor escalation contacts.
2. **Golden Sample NDJSON** (`valid-events.ndjson`) covering every implemented event type so the SOC can build and test DCR/parsers before production cutover.
3. **CI Validation & Signal-to-Noise Report** from `scripts/validate_logs.py --strict` and `scripts/score_signal_noise.py`.
4. **Starter Detections** adapted from [`detections/`](../detections/README.md) (Sigma, Sentinel KQL, or Splunk SPL).

---

## 5. Pre-Go-Live Smoke Test ("Purple Team Check")

Run a 15-minute live end-to-end test in UAT/Staging before production launch:

1. Generate synthetic attack events via `scripts/generate_test_events.py --scenario all` (or trigger real UAT actions: 5 failed logins + 1 success, 1 HTTP 403, 1 role assignment, 1 bulk export).
2. Confirm events arrive in the SIEM within the agency's latency SLA (typically `< 5 minutes`).
3. Confirm all required fields parse cleanly without regex errors or truncation.
4. Confirm at least one starter detection rule fires and creates a test incident with the right `actor.id`, `source.ip`, `target.id`, and `correlation_id`.
5. Confirm **zero** health checks, debug traces, passwords, tokens, or unredacted PII landed in the SIEM table.
