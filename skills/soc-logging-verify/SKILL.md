---
name: soc-logging-verify
description: Verify an application's emitted security logs with automated unit/integration tests, strict JSON schema validation, secret/PII redaction checks, CWE-117 log injection tests, and SOC Signal-to-Noise scoring (>= 90/100).
---

# SOC Logging Verification & CI Gate

Use this skill after implementing security logging (or before any government UAT / ATO release) to prove the emitted logs are high-value, low-noise, schema-valid, and free of leaks.

## Verification Steps

1. **Write automated positive & negative security logging tests** in the project's native test runner using [`references/test-scenarios.md`](./references/test-scenarios.md):
   - Positive tests for implemented P1 events (`authn_*`, `authz_fail`, `priv_*`, `data_bulk_export`, `sys_logging_heartbeat`).
   - Negative redaction tests passing synthetic passwords, Bearer JWTs, API keys, and Australian TFN/Medicare patterns -> assert `[REDACTED]` and zero raw secret presence.
   - Negative CWE-117 log-injection tests passing `\r\n` forged log lines and ANSI escape codes in `username` and `User-Agent` -> assert output remains exactly 1 valid JSON line with no raw control chars.
   - Negative noise tests confirming `/healthz`, static assets, and `DEBUG` logs do NOT emit with `stream: "security"`.

2. **Capture emitted NDJSON from the test suite** into a temporary file (e.g., `tmp/security-events.ndjson`).

3. **Run the zero-dependency validation & scoring gates** (if `soc-ready-logging/scripts/` is available):
   ```bash
   python3 /path/to/soc-ready-logging/scripts/validate_logs.py tmp/security-events.ndjson --strict
   python3 /path/to/soc-ready-logging/scripts/score_signal_noise.py tmp/security-events.ndjson --min-score 90
   python3 /path/to/soc-ready-logging/scripts/audit_repo_logging.py src/ --fail-on-high
   ```

4. **Fix any failing checks immediately**
   - Required pass bar:
     - `validate_logs.py --strict`: `0` errors
     - `score_signal_noise.py`: `>= 90 / 100` (Grade A)
     - `audit_repo_logging.py`: `0` HIGH findings
     - P95 payload size: `<= 2048` bytes

5. **Wire the gate into CI/CD** (GitHub Actions, Azure DevOps, GitLab CI) so future PRs cannot reintroduce noisy logs, schema drift, or secret leakage.
