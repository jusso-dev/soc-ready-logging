# Scripts & CI Tooling

All CLI scripts use **Python 3.9+ standard library only** (plus POSIX Bash for `install-skills.sh`), so they run out of the box on developer laptops, CI runners, and locked-down/air-gapped government build environments with zero `pip install` or `npm install` steps.

| Script | Purpose | Example |
|---|---|---|
| [`validate_logs.py`](./validate_logs.py) | Validate NDJSON logs against the canonical schema, OWASP taxonomy, UTC timestamps, secret/PII redaction, CWE-117 injection safety, and noise checks | `python3 scripts/validate_logs.py schemas/examples/valid-events.ndjson --strict` |
| [`score_signal_noise.py`](./score_signal_noise.py) | Compute a 0–100 SOC Signal-to-Noise Scorecard + estimated SIEM GB per 1M events | `python3 scripts/score_signal_noise.py schemas/examples/valid-events.ndjson --min-score 90` |
| [`generate_test_events.py`](./generate_test_events.py) | Generate realistic synthetic attack & heartbeat NDJSON events for SIEM/detection testing | `python3 scripts/generate_test_events.py --app-id my-gov-app --scenario all --out tmp/test.ndjson` |
| [`audit_repo_logging.py`](./audit_repo_logging.py) | Static codebase scanner (TS/JS, Python, C#, Go, Java) flagging secret/PII log leaks, noise, unstructured stdout prints, and missing canonical events | `python3 scripts/audit_repo_logging.py /path/to/app --markdown` |
| [`generate_soc_handoff.py`](./generate_soc_handoff.py) | Generate a tailored Day-1 Government SOC Handoff Pack from a repo scan or NDJSON sample | `python3 scripts/generate_soc_handoff.py --app-id my-gov-app --app-name "Grants Portal" --from-ndjson schemas/examples/valid-events.ndjson` |
| [`install-skills.sh`](./install-skills.sh) | Install the 4 portable AI coding agent skills (`SKILL.md`) into Claude Code, Codex, Cursor, Antigravity, Copilot, OpenCode, or `.agents/skills` | `./scripts/install-skills.sh --target claude --scope project --project-dir /path/to/app` |

---

## CI Quality Gate Example (GitHub Actions)

Drop these 3 lines into your application's CI workflow after your integration tests emit security logs to `artifacts/security-events.ndjson`:

```yaml
- name: Validate SOC-ready security logs
  run: |
    python3 scripts/validate_logs.py artifacts/security-events.ndjson --strict
    python3 scripts/score_signal_noise.py artifacts/security-events.ndjson --min-score 90
    python3 scripts/audit_repo_logging.py src/ --fail-on-high
```
