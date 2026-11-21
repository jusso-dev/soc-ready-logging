# Security Logging Acceptance Checklist (UAT / ATO Gate)

Use this pass/fail checklist for pre-release engineering sign-off and Government SOC onboarding acceptance.

| # | Control / Requirement | Reference | Verification Method | Pass / Fail |
|---|---|---|---|---|
| 1 | Two-stream separation enforced (`stream: "security"` isolated from debug/health/perf) | ACSC Priority Logs | Inspect collector config + `score_signal_noise.py` (`0%` noise) | [ ] |
| 2 | 100% of security events validate against `schemas/security-event.schema.json` | OWASP Logging Vocab / ISM-0585 | `python3 scripts/validate_logs.py <capture.ndjson> --strict` | [ ] |
| 3 | All timestamps are UTC ISO-8601 (`...Z`) from NTP-synchronized hosts | ACSC ISM-0988 | Schema validator + host NTP check | [ ] |
| 4 | True client IP captured behind WAF / gateway (not internal LB IP) | ISM-0585 / OWASP | Trigger UAT request via WAF and verify `source.ip` | [ ] |
| 5 | Every request carries a `correlation_id` matching gateway/WAF trace ID | OWASP ASVS V16.3 | Correlate 1 test request across WAF + App SIEM tables | [ ] |
| 6 | Zero secrets, tokens, JWTs, passwords, or unredacted TFNs/Medicare/PANs in logs | OWASP ASVS V7.1 / Privacy Act | Negative test sending fake Bearer/password/TFN -> confirm `[REDACTED]` | [ ] |
| 7 | Log injection (CWE-117) blocked (`\r`, `\n`, ANSI escapes stripped/escaped) | OWASP Logging CS | Negative test submitting `user\nFAKE` -> confirm single-line JSON | [ ] |
| 8 | Generic, non-leaking errors returned to users (no stack traces/SQL) | OWASP ASVS V7.4 / V16.5 | Trigger 403 & 500 -> confirm only opaque error + `correlation_id` | [ ] |
| 9 | Signal-to-Noise score `>= 90/100` on representative staging/load capture | ACSC Priority Logs | `python3 scripts/score_signal_noise.py <capture.ndjson>` | [ ] |
| 10 | Out-of-process, write-only SIEM delivery (app cannot alter/delete SIEM logs) | ACSC ISM-1405 / ISM-1815 | Review IAM/RBAC role for app runtime vs. collector | [ ] |
| 11 | `sys_logging_heartbeat` arriving every 15–60 min + SOC absence alert configured | ACSC ISM-1228 / ASVS V16.4 | Confirm heartbeat event in SIEM + alert rule enabled | [ ] |
| 12 | Day-1 SOC Handoff Pack + starter detections delivered & smoke-tested (attach signed `bower evidence run` bundle if using [Bower](https://github.com/jusso-dev/Bower)) | ACSC ISM-0580 / ISM-1228 | Synthetic attack event fires test SOC alert within SLA + signed arrival evidence | [ ] |

---

**Vendor Tech Lead Sign-Off**: _________________________  **Date**: ____________

**Agency SOC / Security Lead Sign-Off**: _________________________  **Date**: ____________
