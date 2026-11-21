# GCP Terraform Starter: Two-Stream Security Logging Sink + Locked Audit Bucket
# Routes ONLY `jsonPayload.stream="security"` to an isolated Security Project's
# Pub/Sub topic (for Google SecOps / Sentinel WIF CCF / jusso-dev/Bower bower-cloud)
# and an immutable 400-day Locked Log Bucket in australia-southeast1.

variable "workload_project_id" {
  type        = string
  description = "GCP project hosting the vendor application."
}

variable "security_project_id" {
  type        = string
  description = "Isolated GCP security/logging project (ACSC ISM-1405)."
}

variable "region" {
  type    = string
  default = "australia-southeast1"
}

resource "google_pubsub_topic" "security_events" {
  project = var.security_project_id
  name    = "app-security-events"
  message_storage_policy {
    allowed_persistence_regions = [var.region, "australia-southeast2"]
  }
}

resource "google_pubsub_topic" "security_events_dlq" {
  project = var.security_project_id
  name    = "app-security-events-dlq"
  message_storage_policy {
    allowed_persistence_regions = [var.region, "australia-southeast2"]
  }
}

resource "google_pubsub_subscription" "siem_or_bower" {
  project = var.security_project_id
  name    = "app-security-events-siem-sub"
  topic   = google_pubsub_topic.security_events.id

  ack_deadline_seconds       = 60
  message_retention_duration = "604800s" # 7 days replay window

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.security_events_dlq.id
    max_delivery_attempts = 10
  }
}

# Tamper-evident Locked Log Bucket (400 days >= 12 months per ACSC ISM-1815 / ISM-1988)
resource "google_logging_project_bucket_config" "security_archive" {
  project        = var.security_project_id
  location       = var.region
  bucket_id      = "soc-security-archive"
  retention_days = 400
  locked         = true
}

resource "google_logging_project_sink" "to_pubsub" {
  project                = var.workload_project_id
  name                   = "soc-security-events-pubsub"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.security_events.id}"
  filter                 = "jsonPayload.stream=\"security\" AND jsonPayload.severity=(\"INFO\" OR \"WARN\" OR \"HIGH\" OR \"CRITICAL\")"
  unique_writer_identity = true
}

resource "google_logging_project_sink" "to_locked_bucket" {
  project                = var.workload_project_id
  name                   = "soc-security-events-archive"
  destination            = "logging.googleapis.com/${google_logging_project_bucket_config.security_archive.id}"
  filter                 = "jsonPayload.stream=\"security\" AND jsonPayload.severity=(\"INFO\" OR \"WARN\" OR \"HIGH\" OR \"CRITICAL\")"
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  project = var.security_project_id
  topic   = google_pubsub_topic.security_events.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.to_pubsub.writer_identity
}

resource "google_project_iam_member" "archive_writer" {
  project = var.security_project_id
  role    = "roles/logging.bucketWriter"
  member  = google_logging_project_sink.to_locked_bucket.writer_identity
}

# Drop noisy health probes from the operational _Default bucket (never drops stream="security")
resource "google_logging_project_exclusion" "drop_health_probes" {
  project     = var.workload_project_id
  name        = "drop-operational-health-probes"
  description = "Exclude k8s/LB health probes from _Default operational bucket"
  filter      = "httpRequest.requestUrl=~\"^/(healthz|readyz|livez|metrics)\" AND NOT jsonPayload.stream=\"security\""
}
