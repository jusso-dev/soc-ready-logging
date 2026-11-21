#!/usr/bin/env python3
"""Validate NDJSON/JSON security logs against the canonical SOC-ready contract.

Zero external dependencies (Python 3.9+ stdlib only). Checks:
  1. Single-line JSON parsing (NDJSON)
  2. Required canonical fields & allowed enum values
  3. UTC ISO-8601 timestamp format (ACSC ISM-0988)
  4. OWASP event prefix & catalog membership
  5. Secret & regulated PII leakage (passwords, Bearer/JWT, PEM, TFN, PAN, sensitive keys)
  6. CWE-117 log injection (embedded newlines, control chars, ANSI escape sequences)
  7. SIEM noise contamination (health probes, static assets, DEBUG/TRACE)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "schemas" / "event-catalog.json"

UTC_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
EVENT_NAME_RE = re.compile(
    r"^(authn|authz|session|user|priv|data|sys|config|input|api|crypto|tamper)_[a-z0-9_]+$"
)
APP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
CORRELATION_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
SESSION_HASH_RE = re.compile(r"^sha256:[a-f0-9]{16,64}$")

ALLOWED_SEVERITIES = {"INFO", "WARN", "HIGH", "CRITICAL"}
ALLOWED_OUTCOMES = {"success", "failure", "blocked", "unknown"}
ALLOWED_ENVIRONMENTS = {"prod", "staging", "uat", "test", "dev"}
ALLOWED_ACTOR_TYPES = {"user", "admin", "service", "api_client", "anonymous", "system"}
ALLOWED_CATEGORIES = {
    "authentication",
    "authorization",
    "session",
    "iam",
    "privilege",
    "data_access",
    "system",
    "configuration",
    "input_validation",
    "api",
    "cryptography",
    "tamper",
}
ALLOWED_CLASSIFICATIONS = {
    "UNOFFICIAL",
    "OFFICIAL",
    "OFFICIAL:Sensitive",
    "PROTECTED",
    "PUBLIC",
    "INTERNAL",
    "CONFIDENTIAL",
    "RESTRICTED",
}

SENSITIVE_KEY_RE = re.compile(
    r"(^|[._-])(pass(word|wd|phrase)?|secret|token|authorization|cookie|"
    r"api[_-]?key|private[_-]?key|tfn|medicare|ssn|credit[_-]?card|card[_-]?number|cvv|pin|otp)($|[._-])",
    re.IGNORECASE,
)

SECRET_VALUE_CHECKS: List[Tuple[str, re.Pattern[str]]] = [
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{12,}=*", re.IGNORECASE)),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("inline_secret_assignment", re.compile(r"\b(password|passwd|pwd|api_key|secret)\s*[:=]\s*(?!\[REDACTED\])\S+", re.IGNORECASE)),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("au_tfn_contextual", re.compile(r"\b(tfn|tax[\s_-]*file[\s_-]*(number|no)?)\b\s*[:=#-]?\s*(?!\[REDACTED\])(\d[\s-]?){8,9}\b", re.IGNORECASE)),
    ("au_medicare_contextual", re.compile(r"\bmedicare(\s*(number|no|card))?\b\s*[:=#-]?\s*(?!\[REDACTED\])[2-6]\d{3}[\s-]?\d{5}[\s-]?\d\b", re.IGNORECASE)),
    ("credit_card_like", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
]

NOISE_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("health_probe", re.compile(r"/(healthz?|readyz?|livez?|metrics)\b", re.IGNORECASE)),
    ("static_asset", re.compile(r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|map)\b", re.IGNORECASE)),
    ("debug_level", re.compile(r"\b(DEBUG|TRACE)\b")),
]

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def load_catalog_events(catalog_path: Path = CATALOG_PATH) -> Set[str]:
    if not catalog_path.exists():
        return set()
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    return {item["event"] for item in data.get("events", []) if "event" in item}


def walk_strings(obj: Any, path: str = "") -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    if isinstance(obj, str):
        found.append((path, obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            sub_path = f"{path}.{k}" if path else str(k)
            found.extend(walk_strings(v, sub_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(walk_strings(item, f"{path}[{i}]"))
    return found


def walk_keys(obj: Any, path: str = "") -> List[Tuple[str, str, Any]]:
    found: List[Tuple[str, str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub_path = f"{path}.{k}" if path else str(k)
            found.append((sub_path, str(k), v))
            found.extend(walk_keys(v, sub_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(walk_keys(item, f"{path}[{i}]"))
    return found


def validate_record(
    record: Dict[str, Any],
    line_no: int,
    catalog_events: Set[str],
    strict: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    def add_err(code: str, msg: str) -> None:
        errors.append({"line": line_no, "code": code, "message": msg})

    def add_warn(code: str, msg: str) -> None:
        warnings.append({"line": line_no, "code": code, "message": msg})

    required_fields = [
        "schema_version",
        "timestamp",
        "stream",
        "event",
        "severity",
        "outcome",
        "app",
        "actor",
        "source",
        "correlation_id",
        "message",
    ]
    for field in required_fields:
        if field not in record:
            add_err("missing_required_field", f"Missing required field '{field}'")

    if record.get("schema_version") != "1.0.0":
        add_err("invalid_schema_version", f"schema_version must be '1.0.0', got {record.get('schema_version')!r}")

    if record.get("stream") != "security":
        add_err("invalid_stream", f"stream must be 'security', got {record.get('stream')!r}")

    ts = record.get("timestamp")
    if not isinstance(ts, str) or not UTC_ISO_RE.match(ts):
        add_err("invalid_timestamp", f"timestamp must be UTC ISO-8601 ending in Z, got {ts!r}")

    ev = record.get("event")
    if not isinstance(ev, str) or not EVENT_NAME_RE.match(ev):
        add_err("invalid_event_name", f"event '{ev}' does not match OWASP-aligned prefix taxonomy")
    elif catalog_events and ev not in catalog_events:
        msg = f"event '{ev}' is not in schemas/event-catalog.json"
        if strict:
            add_err("unknown_catalog_event", msg)
        else:
            add_warn("unknown_catalog_event", msg)

    sev = record.get("severity")
    if sev not in ALLOWED_SEVERITIES:
        add_err("invalid_severity", f"severity must be one of {sorted(ALLOWED_SEVERITIES)}, got {sev!r}")

    outcome = record.get("outcome")
    if outcome not in ALLOWED_OUTCOMES:
        add_err("invalid_outcome", f"outcome must be one of {sorted(ALLOWED_OUTCOMES)}, got {outcome!r}")

    category = record.get("category")
    if category is not None and category not in ALLOWED_CATEGORIES:
        add_err("invalid_category", f"category '{category}' is not an allowed value")

    app = record.get("app")
    if isinstance(app, dict):
        for req in ("id", "name", "environment", "version"):
            if not app.get(req):
                add_err("missing_app_field", f"app.{req} is required")
        if isinstance(app.get("id"), str) and not APP_ID_RE.match(app["id"]):
            add_err("invalid_app_id", f"app.id '{app['id']}' must be lowercase slug")
        if app.get("environment") not in ALLOWED_ENVIRONMENTS:
            add_err("invalid_environment", f"app.environment must be one of {sorted(ALLOWED_ENVIRONMENTS)}")
    elif app is not None:
        add_err("invalid_app_type", "app must be an object")

    actor = record.get("actor")
    if isinstance(actor, dict):
        if actor.get("type") not in ALLOWED_ACTOR_TYPES:
            add_err("invalid_actor_type", f"actor.type must be one of {sorted(ALLOWED_ACTOR_TYPES)}")
        if not actor.get("id"):
            add_err("missing_actor_id", "actor.id is required")
        sid = actor.get("session_id_hash")
        if sid is not None and (not isinstance(sid, str) or not SESSION_HASH_RE.match(sid)):
            add_err("invalid_session_hash", "actor.session_id_hash must match 'sha256:<16-64 hex>'")
    elif actor is not None:
        add_err("invalid_actor_type", "actor must be an object")

    source = record.get("source")
    if isinstance(source, dict):
        if not source.get("ip"):
            add_err("missing_source_ip", "source.ip is required")
    elif source is not None:
        add_err("invalid_source_type", "source must be an object")

    target = record.get("target")
    if isinstance(target, dict):
        cls = target.get("classification")
        if cls is not None and cls not in ALLOWED_CLASSIFICATIONS:
            add_err("invalid_classification", f"target.classification '{cls}' is not an allowed value")

    corr = record.get("correlation_id")
    if not isinstance(corr, str) or not CORRELATION_RE.match(corr):
        add_err("invalid_correlation_id", f"correlation_id must be 8-128 safe chars, got {corr!r}")

    message = record.get("message")
    if not isinstance(message, str) or len(message) < 4 or len(message) > 512:
        add_err("invalid_message", "message must be a string between 4 and 512 characters")

    details = record.get("details")
    if isinstance(details, dict) and len(details) > 25:
        add_err("details_too_many_keys", f"details has {len(details)} keys (max 25)")

    # Secret key check
    for key_path, key_name, val in walk_keys(record):
        if key_name == "session_id_hash":
            continue
        if SENSITIVE_KEY_RE.search(key_name) and val not in ("[REDACTED]", None, ""):
            add_err("sensitive_key_unredacted", f"Sensitive key '{key_path}' is not redacted")

    # Value checks: secrets, CWE-117 injection, and noise markers
    for field_path, text in walk_strings(record):
        if ANSI_RE.search(text) or CONTROL_CHAR_RE.search(text):
            add_err("cwe_117_log_injection", f"Control character or ANSI escape detected in '{field_path}'")
        for secret_kind, regex in SECRET_VALUE_CHECKS:
            if secret_kind == "credit_card_like" and field_path in ("correlation_id", "actor.id", "actor.session_id_hash"):
                continue
            if regex.search(text):
                # Avoid flagging pure UUIDs/hashes as credit cards
                if secret_kind == "credit_card_like":
                    digits = re.sub(r"\D", "", text)
                    if not (13 <= len(digits) <= 16 and text.replace(" ", "").replace("-", "").isdigit()):
                        continue
                hint = " (consider jusso-dev/Bower for host-side AU PII protection)" if secret_kind.startswith("au_") else ""
                add_err("secret_or_pii_leak", f"Potential {secret_kind} detected in '{field_path}'{hint}")
        if field_path in ("message", "http.route", "target.name"):
            for noise_kind, nregex in NOISE_PATTERNS:
                if noise_kind == "debug_level" and field_path != "message":
                    continue
                if nregex.search(text):
                    if strict:
                        add_err("noise_contamination", f"Potential SIEM noise ({noise_kind}) detected in '{field_path}'")
                    else:
                        add_warn("noise_contamination", f"Potential SIEM noise ({noise_kind}) detected in '{field_path}'")

    return errors, warnings


def validate_file(path: Path, strict: bool = False) -> Dict[str, Any]:
    catalog_events = load_catalog_events()
    lines = path.read_text(encoding="utf-8").splitlines()
    total_records = 0
    valid_records = 0
    all_errors: List[Dict[str, Any]] = []
    all_warnings: List[Dict[str, Any]] = []

    for idx, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        total_records += 1
        try:
            parsed = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            all_errors.append({"line": idx, "code": "invalid_json", "message": f"Invalid JSON: {exc}"})
            continue

        if not isinstance(parsed, dict):
            all_errors.append({"line": idx, "code": "not_json_object", "message": "Each NDJSON line must be a JSON object"})
            continue

        errs, warns = validate_record(parsed, idx, catalog_events, strict=strict)
        all_errors.extend(errs)
        all_warnings.extend(warns)
        if not errs:
            valid_records += 1

    return {
        "file": str(path),
        "total_records": total_records,
        "valid_records": valid_records,
        "invalid_records": total_records - valid_records,
        "error_count": len(all_errors),
        "warning_count": len(all_warnings),
        "passed": len(all_errors) == 0 and total_records > 0,
        "errors": all_errors,
        "warnings": all_warnings,
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate NDJSON security logs against the canonical SOC-ready schema.")
    parser.add_argument("input", type=Path, help="Path to NDJSON log file")
    parser.add_argument("--strict", action="store_true", help="Treat unknown catalog events and noise markers as errors")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable JSON output")
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        return 2

    report = validate_file(args.input, strict=args.strict)

    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        status = "PASS" if report["passed"] else "FAIL"
        print(f"[{status}] {report['file']}")
        print(
            f"  Records: {report['total_records']} total | {report['valid_records']} valid | "
            f"{report['invalid_records']} invalid | {report['error_count']} errors | {report['warning_count']} warnings"
        )
        for err in report["errors"][:30]:
            print(f"  ERROR   line {err['line']}: [{err['code']}] {err['message']}")
        for warn in report["warnings"][:20]:
            print(f"  WARN    line {warn['line']}: [{warn['code']}] {warn['message']}")

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
