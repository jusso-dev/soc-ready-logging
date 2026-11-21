#!/usr/bin/env python3
"""Score a security log capture for SOC Signal-to-Noise quality (0-100).

Evaluates 5 weighted pillars:
  - Schema compliance (30 pts)
  - Secret, PII & CWE-117 injection safety (30 pts)
  - Noise discipline: zero debug/health/static contamination (20 pts)
  - Payload compactness: P95 event size <= 2048 bytes (10 pts)
  - Canonical OWASP catalogue alignment (10 pts)
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from validate_logs import load_catalog_events, validate_file  # noqa: E402


def percentile(values: List[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil((pct / 100.0) * len(ordered)) - 1))
    return ordered[index]


def score_file(path: Path) -> Dict[str, Any]:
    validation = validate_file(path, strict=True)
    catalog_events = load_catalog_events()

    raw_lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    total = len(raw_lines)
    if total == 0:
        return {
            "file": str(path),
            "total_records": 0,
            "score": 0,
            "grade": "F",
            "breakdown": {},
            "recommendations": ["No log records found in file."],
        }

    sizes = [len(line.encode("utf-8")) for line in raw_lines]
    p95_bytes = percentile(sizes, 95)
    avg_bytes = round(sum(sizes) / total, 1)

    event_counts: Counter[str] = Counter()
    catalog_matches = 0
    for line in raw_lines:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and isinstance(obj.get("event"), str):
                ev = obj["event"]
                event_counts[ev] += 1
                if ev in catalog_events:
                    catalog_matches += 1
        except json.JSONDecodeError:
            continue

    errors = validation["errors"]
    safety_codes = {"secret_or_pii_leak", "sensitive_key_unredacted", "cwe_117_log_injection"}
    noise_codes = {"noise_contamination", "invalid_severity", "invalid_stream"}

    safety_lines = {e["line"] for e in errors if e["code"] in safety_codes}
    noise_lines = {e["line"] for e in errors if e["code"] in noise_codes}
    schema_lines = {
        e["line"]
        for e in errors
        if e["code"] not in safety_codes and e["code"] not in noise_codes and e["code"] != "unknown_catalog_event"
    }

    # Weighted scores
    schema_score = round(30.0 * (1.0 - len(schema_lines) / total), 1)
    # Any secret/PII or injection leak is heavily penalised
    safety_score = 0.0 if safety_lines else 30.0
    noise_score = round(20.0 * (1.0 - len(noise_lines) / total), 1)

    if p95_bytes <= 2048:
        compact_score = 10.0
    elif p95_bytes <= 4096:
        compact_score = 6.0
    elif p95_bytes <= 8192:
        compact_score = 3.0
    else:
        compact_score = 0.0

    catalog_score = round(10.0 * (catalog_matches / total), 1)
    total_score = round(schema_score + safety_score + noise_score + compact_score + catalog_score, 1)

    if total_score >= 90:
        grade = "A"
    elif total_score >= 80:
        grade = "B"
    elif total_score >= 70:
        grade = "C"
    elif total_score >= 55:
        grade = "D"
    else:
        grade = "F"

    recommendations: List[str] = []
    if safety_lines:
        recommendations.append(
            f"CRITICAL: Fix {len(safety_lines)} record(s) containing unredacted secrets/PII or CWE-117 control characters."
        )
    if noise_lines:
        recommendations.append(
            f"Route {len(noise_lines)} noisy record(s) (debug/health/static/non-security stream) to operational telemetry instead of SIEM."
        )
    if schema_lines:
        recommendations.append(
            f"Fix schema contract violations on {len(schema_lines)} record(s) (run validate_logs.py for line-by-line details)."
        )
    if p95_bytes > 2048:
        recommendations.append(
            f"Trim oversized payloads (P95={p95_bytes} bytes; target <= 2048 bytes) by removing stack traces and raw bodies."
        )
    if catalog_matches < total:
        recommendations.append(
            f"Map {total - catalog_matches} event(s) to standardised OWASP event names in schemas/event-catalog.json."
        )
    if not recommendations:
        recommendations.append("Excellent SOC readiness: high signal, zero noise, zero leaks, and full schema compliance.")

    est_gb_per_million = round((avg_bytes * 1_000_000) / (1024**3), 3)

    return {
        "file": str(path),
        "total_records": total,
        "score": total_score,
        "grade": grade,
        "avg_bytes": avg_bytes,
        "p95_bytes": p95_bytes,
        "est_gb_per_1m_events": est_gb_per_million,
        "distinct_events": len(event_counts),
        "top_events": event_counts.most_common(10),
        "breakdown": {
            "schema_compliance_30": schema_score,
            "safety_redaction_30": safety_score,
            "noise_discipline_20": noise_score,
            "payload_compactness_10": compact_score,
            "catalog_alignment_10": catalog_score,
        },
        "recommendations": recommendations,
    }


def render_markdown(report: Dict[str, Any]) -> str:
    b = report["breakdown"]
    lines = [
        f"# SOC Signal-to-Noise Scorecard: `{report['file']}`",
        "",
        f"**Overall Score:** `{report['score']} / 100` (Grade **{report['grade']}**)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total Records Analysed | `{report['total_records']}` |",
        f"| Distinct Event Types | `{report['distinct_events']}` |",
        f"| Average / P95 Payload Size | `{report['avg_bytes']} B` / `{report['p95_bytes']} B` |",
        f"| Estimated SIEM Volume / 1M Events | `{report['est_gb_per_1m_events']} GB` |",
        "",
        "## Pillar Breakdown",
        "",
        "| Pillar | Score | Max |",
        "|---|---:|---:|",
        f"| Schema Compliance | {b.get('schema_compliance_30', 0)} | 30 |",
        f"| Secret, PII & CWE-117 Safety | {b.get('safety_redaction_30', 0)} | 30 |",
        f"| Noise Discipline (Zero Debug/Health/Static) | {b.get('noise_discipline_20', 0)} | 20 |",
        f"| Payload Compactness (<= 2 KB P95) | {b.get('payload_compactness_10', 0)} | 10 |",
        f"| OWASP Catalogue Alignment | {b.get('catalog_alignment_10', 0)} | 10 |",
        "",
        "## Recommendations",
        "",
    ]
    for rec in report["recommendations"]:
        lines.append(f"- {rec}")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score an NDJSON log capture for SOC Signal-to-Noise quality.")
    parser.add_argument("input", type=Path, help="Path to NDJSON log file")
    parser.add_argument("--min-score", type=float, default=0.0, help="Fail with exit code 1 if score is below threshold")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")
    parser.add_argument("--markdown", action="store_true", help="Emit Markdown scorecard")
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        return 2

    report = score_file(args.input)

    if args.as_json:
        print(json.dumps(report, indent=2))
    elif args.markdown:
        print(render_markdown(report))
    else:
        b = report["breakdown"]
        print(f"Signal-to-Noise Score: {report['score']}/100 (Grade {report['grade']}) | {report['file']}")
        print(
            f"  Schema: {b.get('schema_compliance_30', 0)}/30 | Safety: {b.get('safety_redaction_30', 0)}/30 | "
            f"Noise: {b.get('noise_discipline_20', 0)}/20 | Size: {b.get('payload_compactness_10', 0)}/10 | "
            f"Catalogue: {b.get('catalog_alignment_10', 0)}/10"
        )
        print(
            f"  Records: {report['total_records']} | Avg: {report['avg_bytes']} B | "
            f"P95: {report['p95_bytes']} B | Est: {report['est_gb_per_1m_events']} GB per 1M events"
        )
        for rec in report["recommendations"]:
            print(f"  -> {rec}")

    return 0 if report["score"] >= args.min_score else 1


if __name__ == "__main__":
    raise SystemExit(main())
