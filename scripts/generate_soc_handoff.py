#!/usr/bin/env python3
"""Generate a tailored Day-1 Government SOC Handoff Pack Markdown document.

Combines application metadata with either a comma-separated list of implemented
events or an automatic scan of a codebase directory / sample NDJSON log file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "schemas" / "event-catalog.json"

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_repo_logging import audit_directory  # noqa: E402


def load_catalog_map() -> Dict[str, Dict[str, Any]]:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    return {item["event"]: item for item in data.get("events", [])}


def extract_events_from_ndjson(ndjson_path: Path) -> Set[str]:
    events: Set[str] = set()
    for line in ndjson_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and isinstance(obj.get("event"), str):
                events.add(obj["event"])
        except json.JSONDecodeError:
            continue
    return events


def generate_handoff_markdown(
    *,
    app_id: str,
    app_name: str,
    classification: str,
    siem: str,
    transport: str,
    idp: str,
    events: List[str],
    catalog_map: Dict[str, Dict[str, Any]],
) -> str:
    rows: List[str] = []
    for ev in sorted(events):
        meta = catalog_map.get(ev)
        if meta:
            mitre = ", ".join(meta.get("mitre_attack", [])) or "-"
            ism = ", ".join(meta.get("ism_refs", [])) or "-"
            rows.append(
                f"| `{ev}` | `{meta['category']}` | `{meta['default_severity']}` | `{meta['siem_priority']}` | "
                f"{mitre} | {ism} | {meta['description']} |"
            )
        else:
            rows.append(f"| `{ev}` | `custom` | `INFO` | `P2` | - | ISM-0585 | Custom event (consider aligning to catalogue) |")

    event_table = "\n".join(rows) if rows else "| _(none specified)_ | - | - | - | - | - | - |"

    return f"""# Day-1 SOC Handoff Pack: {app_name} (`{app_id}`)

Generated with `soc-ready-logging` (`v1.0.0` canonical schema, OWASP + ACSC ISM aligned).

---

## 1. Application Profile

| Field | Value |
|---|---|
| **Application ID (`app.id`)** | `{app_id}` |
| **Application Name (`app.name`)** | {app_name} |
| **Data Classification (PSPF / Sensitivity)** | `{classification}` |
| **Target SIEM** | {siem} |
| **Log Transport** | {transport} |
| **Identity Provider (IdP)** | {idp} |
| **Stream Filter** | `stream == "security"` (operational/debug logs excluded from SIEM) |
| **Timestamp Standard** | UTC ISO-8601 (`...Z`), NTP-synchronised (ACSC ISM-0988) |
| **Heartbeat Expectation** | `sys_logging_heartbeat` every 15–60 min; alert if silent > 90 min |

---

## 2. Implemented Security Event Catalogue ({len(events)} events)

| Event (`event`) | Category | Severity | Priority | MITRE ATT&CK | ACSC ISM | Description |
|---|---|---|---|---|---|---|
{event_table}

---

## 3. Day-1 Starter SIEM Query ({siem})

```kql
// Microsoft Sentinel KQL: High-priority security events for {app_id}
CustomAppSecurity_CL
| where TimeGenerated > ago(24h)
| where stream == "security" and tostring(app.id) == "{app_id}" and tostring(app.environment) == "prod"
| where severity in ("HIGH", "CRITICAL") or event in ("authn_login_success_after_fail", "authz_fail", "priv_role_assigned", "data_bulk_export", "tamper_logging_disabled_or_cleared")
| project TimeGenerated, event, severity, outcome, ActorId = tostring(actor.id), SrcIp = tostring(source.ip), TargetId = tostring(target.id), message, correlation_id
| order by TimeGenerated desc
```

---

## 4. Pre-Go-Live Verification Checklist

- [ ] `python3 scripts/validate_logs.py <staging-capture.ndjson> --strict` passes with `0` errors
- [ ] `python3 scripts/score_signal_noise.py <staging-capture.ndjson> --min-score 90` passes
- [ ] Synthetic attack replay (`python3 scripts/generate_test_events.py --app-id {app_id} --environment uat`) ingested and alerted in {siem}
- [ ] Known service accounts and scheduled automation documented with the SOC to prevent Day-1 false positives
- [ ] Write-only SIEM ingestion confirmed (application runtime cannot modify or delete ingested logs, per ACSC ISM-1815)
"""


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a Day-1 Government SOC Handoff Pack Markdown document.")
    parser.add_argument("--app-id", required=True, help="Stable lowercase app.id slug")
    parser.add_argument("--app-name", required=True, help="Human-readable application name")
    parser.add_argument("--classification", default="OFFICIAL:Sensitive", help="PSPF or sensitivity classification")
    parser.add_argument("--siem", default="Microsoft Sentinel", help="Target SIEM platform")
    parser.add_argument("--transport", default="stdout NDJSON -> OTel/Fluent Bit -> SIEM DCR", help="Log transport pipeline")
    parser.add_argument("--idp", default="Microsoft Entra ID (OIDC + Phishing-Resistant MFA)", help="Identity provider")
    parser.add_argument("--events", help="Comma-separated list of implemented event names")
    parser.add_argument("--from-ndjson", type=Path, help="Extract implemented events from an NDJSON sample file")
    parser.add_argument("--from-repo", type=Path, help="Scan a repository directory for implemented canonical events")
    parser.add_argument("--out", type=Path, help="Output Markdown path (defaults to stdout)")
    args = parser.parse_args(argv)

    catalog_map = load_catalog_map()
    event_set: Set[str] = set()

    if args.events:
        event_set.update(e.strip() for e in args.events.split(",") if e.strip())
    if args.from_ndjson:
        event_set.update(extract_events_from_ndjson(args.from_ndjson))
    if args.from_repo:
        audit = audit_directory(args.from_repo)
        event_set.update(audit["detected_canonical_events"])
    if not event_set:
        # Default to P1 baseline events from the catalogue
        event_set.update(k for k, v in catalog_map.items() if v.get("siem_priority") == "P1")
        event_set.add("sys_logging_heartbeat")

    markdown = generate_handoff_markdown(
        app_id=args.app_id,
        app_name=args.app_name,
        classification=args.classification,
        siem=args.siem,
        transport=args.transport,
        idp=args.idp,
        events=sorted(event_set),
        catalog_map=catalog_map,
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(markdown, encoding="utf-8")
        print(f"Wrote SOC Handoff Pack to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(markdown)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
