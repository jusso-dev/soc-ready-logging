# Drop-In Collector & Cloud IaC Starter Configs

> [!TIP]
> **Looking for host-side Australian PII redaction (TFN, Medicare, IHI, ABN/ACN, CRN), default-deny signed policies, a tamper-evident queue ledger, and signed Sentinel arrival proof (`bower evidence run`)?**
> Start with **[jusso-dev/Bower](https://github.com/jusso-dev/Bower)** ([Integration Guide](../docs/12-normalising-and-shipping-with-bower.md)).
>
> Use the drop-in collector and IaC templates below when routing `stream == "security"` into Bower or directly into cloud-native SIEM pipelines.

| Target | Starter Config | Guide |
|---|---|---|
| **OpenTelemetry Collector** | [`otel-collector/security-two-stream.yaml`](./otel-collector/security-two-stream.yaml) | [`06-soc-handoff-and-siem-onboarding.md`](../docs/06-soc-handoff-and-siem-onboarding.md) |
| **Fluent Bit / ECS FireLens** | [`fluent-bit/two-stream-router.conf`](./fluent-bit/two-stream-router.conf) | [`09-aws-logging-guide.md`](../docs/09-aws-logging-guide.md) |
| **Azure Monitor DCR (ARM)** | [`azure-dcr/custom-app-security-dcr.json`](./azure-dcr/custom-app-security-dcr.json) | [`08-azure-logging-guide.md`](../docs/08-azure-logging-guide.md) |
| **AWS CloudWatch -> Firehose -> S3 WORM (Terraform)** | [`aws-cloudwatch/subscription-filter.tf`](./aws-cloudwatch/subscription-filter.tf) | [`09-aws-logging-guide.md`](../docs/09-aws-logging-guide.md) |
| **GCP Logging Sink + Locked Bucket (Terraform)** | [`gcp-logging/sink-and-locked-bucket.tf`](./gcp-logging/sink-and-locked-bucket.tf) | [`10-gcp-logging-guide.md`](../docs/10-gcp-logging-guide.md) |
