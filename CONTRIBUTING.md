# Contributing to soc-ready-logging

Contributions from custom software vendors, government security architects, and SOC analysts are warmly welcome.

## What makes a great contribution?

- **Event catalogue additions** (`schemas/event-catalog.json`): New high-value security events with clear OWASP vocabulary alignment, MITRE ATT&CK technique IDs, ACSC ISM / OWASP ASVS mappings, and noise-control notes.
- **Language reference wrappers** (`examples/`): Minimal, dependency-light security logger implementations (e.g., Java, Rust, PHP, Ruby) that follow `schemas/security-event.schema.json`, redact secrets/PII, and strip log-injection characters.
- **Detection rules** (`detections/`): Tested Sigma, Microsoft Sentinel KQL, Splunk SPL, or Elastic EQL/KQL queries targeting events in the canonical schema.
- **Agent skill improvements** (`skills/`): Tighter instructions, sharper verification steps, or framework-specific recipes that reduce vendor implementation effort.
- **Documentation refinements** (`docs/`): Updates tracking new ACSC ISM releases, OWASP ASVS revisions, or real-world government SOC onboarding lessons.

## Local verification

Before opening a pull request, run the full validation suite:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_logs.py schemas/examples/valid-events.ndjson --strict
python3 scripts/score_signal_noise.py schemas/examples/valid-events.ndjson
```

All scripts intentionally use Python 3 standard library only so vendor CI pipelines and air-gapped or restricted government environments can run them without external packages.
