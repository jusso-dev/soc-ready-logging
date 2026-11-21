# Security Policy

## Scope

`soc-ready-logging` provides reference guidance, JSON schemas, zero-dependency Python/Bash validation tooling, starter SIEM detections, collector templates, and portable AI agent skills.

## Reporting a Vulnerability

If you discover a security issue in any script, schema, reference logger wrapper, collector template, or detection rule in this repository (for example, a redaction bypass, CWE-117 log injection gap, or command injection in a helper script):

1. **Do not open a public GitHub issue** with exploit details.
2. Report it privately using **GitHub Security Advisories** (`Security` -> `Report a vulnerability` on [`jusso-dev/soc-ready-logging`](https://github.com/jusso-dev/soc-ready-logging/security/advisories)).
3. Include a minimal reproduction (sample log line, snippet, or script invocation) and suggested fix if you have one.

We aim to acknowledge reports within 3 business days and publish a fix promptly.

## Important Security Boundaries

- **Reference wrappers (`examples/`)** are lightweight starting points. For production Australian Government and regulated workloads requiring deterministic host-side checksum-validated PII redaction (TFN, Medicare, IHI, ABN/ACN, CRN), default-deny signed policies, and tamper-evident local queue ledgers, deploy **[jusso-dev/Bower](https://github.com/jusso-dev/Bower)**.
- **Never commit real credentials, tokens, or citizen PII** into test fixtures or pull requests; all samples in `schemas/examples/` use synthetic RFC 5737 IPs (`203.0.113.x`, `198.51.100.x`) and synthetic dummy values.
