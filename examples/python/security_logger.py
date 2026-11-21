"""Minimal, stdlib-only SOC-ready SecurityLogger (Python 3.9+).

Aligns with OWASP Logging Vocabulary / ASVS V16 and ACSC ISM System Monitoring.
Emits single-line JSON (NDJSON) with `stream: "security"`, automatic secret/PII
redaction, CWE-117 control-character stripping, and UTC ISO-8601 timestamps.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

SENSITIVE_KEY_RE = re.compile(
    r"(pass(word|wd|phrase)?|secret|token|authorization|cookie|"
    r"api[_-]?key|private[_-]?key|tfn|medicare|ssn|credit[_-]?card|cvv|pin|otp)",
    re.IGNORECASE,
)

SECRET_VALUE_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"(password|passwd|pwd|secret|api_key|token)\s*[:=]\s*\S+", re.IGNORECASE),
]

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_string(value: str, max_length: int = 512) -> str:
    clean = ANSI_RE.sub("", value)
    clean = CONTROL_RE.sub(" ", clean)
    for pattern in SECRET_VALUE_PATTERNS:
        clean = pattern.sub("[REDACTED]", clean)
    clean = clean.strip()
    return clean[:max_length]


def redact_value(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return sanitize_string(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [redact_value(item, depth + 1) for item in value[:25]]
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for idx, (k, v) in enumerate(value.items()):
            if idx >= 25:
                break
            key_str = str(k)
            if SENSITIVE_KEY_RE.search(key_str):
                result[key_str] = "[REDACTED]"
            else:
                result[key_str] = redact_value(v, depth + 1)
        return result
    return sanitize_string(str(value))


def hash_session_id(raw_session_id: str, salt: str = "") -> str:
    digest = hashlib.sha256(f"{salt}:{raw_session_id}".encode("utf-8")).hexdigest()[:32]
    return f"sha256:{digest}"


class SecurityLogger:
    def __init__(
        self,
        *,
        app_id: str,
        app_name: str,
        environment: str,
        version: str,
        component: Optional[str] = None,
        host: Optional[str] = None,
        sink: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.app: Dict[str, Any] = {
            "id": app_id,
            "name": app_name,
            "environment": environment,
            "version": version,
            "host": host or socket.gethostname(),
        }
        if component:
            self.app["component"] = component
        self._sink = sink or (lambda line: sys.stdout.write(f"{line}\n"))
        self._emitted_since_heartbeat = 0

    def emit(
        self,
        *,
        event: str,
        severity: str,
        outcome: str,
        actor: Dict[str, Any],
        source: Dict[str, Any],
        message: str,
        category: Optional[str] = None,
        target: Optional[Dict[str, Any]] = None,
        http: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        record: Dict[str, Any] = {
            "schema_version": "1.0.0",
            "timestamp": timestamp,
            "stream": "security",
            "event": sanitize_string(event, 80),
            "severity": severity,
            "outcome": outcome,
            "app": self.app,
            "actor": redact_value(actor),
            "source": redact_value(source),
            "correlation_id": sanitize_string(correlation_id or f"trace-{uuid.uuid4()}", 128),
            "message": sanitize_string(message, 512),
        }
        if category:
            record["category"] = category
        if target:
            record["target"] = redact_value(target)
        if http:
            record["http"] = redact_value(http)
        if reason:
            record["reason"] = sanitize_string(reason, 128)
        if details:
            record["details"] = redact_value(details)

        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
        self._emitted_since_heartbeat += 1
        self._sink(line)
        return line

    def emit_heartbeat(self, interval_seconds: int = 900, dropped_events: int = 0) -> str:
        count = self._emitted_since_heartbeat
        self._emitted_since_heartbeat = 0
        return self.emit(
            event="sys_logging_heartbeat",
            category="system",
            severity="INFO",
            outcome="success",
            actor={"type": "system", "id": "system:audit-heartbeat"},
            source={"ip": "127.0.0.1"},
            message="Security logging pipeline heartbeat OK",
            details={
                "interval_seconds": interval_seconds,
                "events_emitted_since_last": count,
                "dropped_events": dropped_events,
            },
        )
