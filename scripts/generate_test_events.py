#!/usr/bin/env python3
"""Generate realistic synthetic OWASP/ACSC security events for SIEM onboarding & purple-team testing.

Zero external dependencies. Produces valid NDJSON matching schemas/security-event.schema.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


def make_ts(base: datetime, offset_seconds: int) -> str:
    dt = base + timedelta(seconds=offset_seconds)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_event(
    *,
    ts: str,
    app_id: str,
    app_name: str,
    env: str,
    version: str,
    event: str,
    category: str,
    severity: str,
    outcome: str,
    actor: Dict[str, Any],
    source: Dict[str, Any],
    message: str,
    component: str = "core-api",
    target: Dict[str, Any] | None = None,
    http: Dict[str, Any] | None = None,
    reason: str | None = None,
    details: Dict[str, Any] | None = None,
    mitre: List[str] | None = None,
    ism: List[str] | None = None,
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "timestamp": ts,
        "stream": "security",
        "event": event,
        "category": category,
        "severity": severity,
        "outcome": outcome,
        "app": {
            "id": app_id,
            "name": app_name,
            "component": component,
            "environment": env,
            "version": version,
            "host": f"{app_id}-{component}-01.{env}.internal",
        },
        "actor": actor,
        "source": source,
        "correlation_id": f"trace-{uuid.uuid4().hex}",
        "message": message,
    }
    if target:
        record["target"] = target
    if http:
        record["http"] = http
    if reason:
        record["reason"] = reason
    if details:
        record["details"] = details
    if mitre or ism:
        record["compliance"] = {
            "owasp_event": event,
            "mitre_attack": mitre or [],
            "ism_controls": ism or ["ISM-0585", "ISM-1228"],
        }
    return record


def generate_scenarios(scenario: str, app_id: str, app_name: str, env: str, version: str) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    events: List[Dict[str, Any]] = []
    chosen = (
        ["brute-force-takeover", "idor-probe", "privilege-abuse", "bulk-exfil", "tamper-and-heartbeat"]
        if scenario == "all"
        else [scenario]
    )

    if "brute-force-takeover" in chosen:
        for i in range(1, 6):
            events.append(
                build_event(
                    ts=make_ts(now, i * 4),
                    app_id=app_id,
                    app_name=app_name,
                    env=env,
                    version=version,
                    component="auth-api",
                    event="authn_login_fail",
                    category="authentication",
                    severity="WARN",
                    outcome="failure",
                    actor={"type": "user", "id": "oid-target-001", "username": "a.nguyen@agency.gov.au"},
                    source={"ip": "198.51.100.77", "user_agent": "curl/8.7.1", "geo_country": "AU"},
                    http={"method": "POST", "route": "/api/v1/auth/login", "status_code": 401},
                    reason="invalid_credentials",
                    message=f"Authentication failed for user oid-target-001 (attempt {i})",
                    details={"auth_method": "oidc_entra", "attempt_number": i},
                    mitre=["T1110"],
                )
            )
        events.append(
            build_event(
                ts=make_ts(now, 28),
                app_id=app_id,
                app_name=app_name,
                env=env,
                version=version,
                component="auth-api",
                event="authn_login_success_after_fail",
                category="authentication",
                severity="HIGH",
                outcome="success",
                actor={
                    "type": "user",
                    "id": "oid-target-001",
                    "username": "a.nguyen@agency.gov.au",
                    "roles": ["case_officer"],
                    "session_id_hash": "sha256:4e07408562bedb8b60ce05c1decfe3ad",
                },
                source={"ip": "198.51.100.77", "user_agent": "curl/8.7.1", "geo_country": "AU"},
                http={"method": "POST", "route": "/api/v1/auth/login", "status_code": 200},
                reason="valid_credentials",
                message="User oid-target-001 logged in after 5 failed attempts in 30 seconds",
                details={"auth_method": "oidc_entra", "failed_attempts": 5, "window_seconds": 30},
                mitre=["T1110", "T1078"],
            )
        )

    if "idor-probe" in chosen:
        for idx, case_num in enumerate(range(1001, 1007), start=1):
            events.append(
                build_event(
                    ts=make_ts(now, 40 + idx * 3),
                    app_id=app_id,
                    app_name=app_name,
                    env=env,
                    version=version,
                    component="case-api",
                    event="authz_fail",
                    category="authorization",
                    severity="WARN",
                    outcome="blocked",
                    actor={"type": "user", "id": "oid-target-001", "roles": ["case_officer"]},
                    source={"ip": "198.51.100.77", "geo_country": "AU"},
                    target={"type": "case_record", "id": f"case-{case_num}", "classification": "OFFICIAL:Sensitive"},
                    http={"method": "GET", "route": "/api/v1/cases/{id}", "status_code": 403},
                    reason="missing_role",
                    message=f"Access denied to case-{case_num} for user oid-target-001",
                    details={"required_permission": "cases:read:restricted"},
                    mitre=["T1213"],
                )
            )

    if "privilege-abuse" in chosen:
        events.append(
            build_event(
                ts=make_ts(now, 70),
                app_id=app_id,
                app_name=app_name,
                env=env,
                version=version,
                component="admin-api",
                event="priv_role_assigned",
                category="privilege",
                severity="HIGH",
                outcome="success",
                actor={"type": "admin", "id": "oid-admin-999", "roles": ["tenant_admin"]},
                source={"ip": "203.0.113.19", "geo_country": "AU"},
                target={"type": "user", "id": "oid-target-001"},
                http={"method": "POST", "route": "/api/v1/admin/users/{id}/roles", "status_code": 200},
                message="Assigned global_admin role to oid-target-001 without change ticket",
                details={"role_name": "global_admin", "ticket_ref": "none"},
                mitre=["T1098"],
            )
        )
        events.append(
            build_event(
                ts=make_ts(now, 80),
                app_id=app_id,
                app_name=app_name,
                env=env,
                version=version,
                component="auth-api",
                event="authn_mfa_disabled",
                category="authentication",
                severity="CRITICAL",
                outcome="success",
                actor={"type": "admin", "id": "oid-admin-999", "roles": ["tenant_admin"]},
                source={"ip": "203.0.113.19", "geo_country": "AU"},
                target={"type": "user", "id": "oid-target-001"},
                http={"method": "DELETE", "route": "/api/v1/admin/users/{id}/mfa", "status_code": 200},
                message="MFA disabled for user oid-target-001",
                details={"previous_mfa_method": "fido2"},
                mitre=["T1556.006"],
            )
        )

    if "bulk-exfil" in chosen:
        events.append(
            build_event(
                ts=make_ts(now, 95),
                app_id=app_id,
                app_name=app_name,
                env=env,
                version=version,
                component="export-worker",
                event="data_bulk_export",
                category="data_access",
                severity="HIGH",
                outcome="success",
                actor={"type": "user", "id": "oid-target-001", "roles": ["global_admin"]},
                source={"ip": "198.51.100.77", "geo_country": "AU"},
                target={"type": "export", "id": "exp-998811", "name": "all-citizens.csv", "classification": "PROTECTED"},
                http={"method": "POST", "route": "/api/v1/exports", "status_code": 200},
                message="Bulk export of 4820 PROTECTED records completed",
                details={"record_count": 4820, "format": "csv", "dataset": "citizen_registry"},
                mitre=["T1530"],
            )
        )

    if "tamper-and-heartbeat" in chosen:
        events.append(
            build_event(
                ts=make_ts(now, 110),
                app_id=app_id,
                app_name=app_name,
                env=env,
                version=version,
                component="admin-api",
                event="tamper_logging_disabled_or_cleared",
                category="tamper",
                severity="CRITICAL",
                outcome="blocked",
                actor={"type": "admin", "id": "oid-admin-999", "roles": ["tenant_admin"]},
                source={"ip": "203.0.113.19", "geo_country": "AU"},
                target={"type": "audit_pipeline", "id": "security-stream"},
                reason="immutable_policy_enforced",
                message="Blocked attempt to disable security audit stream",
                details={"target_component": "security-stream", "attempted_setting": "enabled=false"},
                mitre=["T1562.008"],
                ism=["ISM-1405", "ISM-1815", "ISM-1228"],
            )
        )
        events.append(
            build_event(
                ts=make_ts(now, 120),
                app_id=app_id,
                app_name=app_name,
                env=env,
                version=version,
                component="audit-pipeline",
                event="sys_logging_heartbeat",
                category="system",
                severity="INFO",
                outcome="success",
                actor={"type": "system", "id": "system:audit-heartbeat"},
                source={"ip": "127.0.0.1"},
                message="Security logging pipeline heartbeat OK",
                details={"interval_seconds": 900, "events_emitted_since_last": len(events), "dropped_events": 0},
                mitre=["T1562.008"],
                ism=["ISM-1405", "ISM-1228"],
            )
        )

    return events


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic OWASP/ACSC security events in NDJSON.")
    parser.add_argument(
        "--scenario",
        choices=["brute-force-takeover", "idor-probe", "privilege-abuse", "bulk-exfil", "tamper-and-heartbeat", "all"],
        default="all",
    )
    parser.add_argument("--app-id", default="gov-sample-app")
    parser.add_argument("--app-name", default="Government Sample Application")
    parser.add_argument("--environment", default="uat", choices=["prod", "staging", "uat", "test", "dev"])
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--out", type=Path, help="Optional file path to write NDJSON (defaults to stdout)")
    args = parser.parse_args(argv)

    events = generate_scenarios(args.scenario, args.app_id, args.app_name, args.environment, args.version)
    output = "\n".join(json.dumps(e, separators=(",", ":")) for e in events) + "\n"

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
        print(f"Wrote {len(events)} synthetic security events to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
