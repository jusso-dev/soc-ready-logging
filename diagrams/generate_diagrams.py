#!/usr/bin/env python3
"""Generate all architecture & cloud diagrams using the Python `diagrams` library.

Uses one consistent font family (`Helvetica`), generous node bounding boxes so
arrows never clip multi-line labels, crisp opaque pill edge labels so lines
never slice through text, and official Azure, AWS, GCP, and OSS icons.

Requirements:
    - Graphviz (`brew install graphviz` or `apt-get install graphviz`)
    - Python `diagrams` (`uv run --with diagrams python3 diagrams/generate_diagrams.py`)
"""

from __future__ import annotations

from html import escape
from pathlib import Path

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.analytics import KinesisDataFirehose
from diagrams.aws.compute import ECS, EKS, Lambda
from diagrams.aws.integration import SQS
from diagrams.aws.management import CloudwatchLogs
from diagrams.aws.security import IAMRole, KMS as AwsKms, SecurityHub, SecurityLake, WAF
from diagrams.aws.storage import S3
from diagrams.azure.analytics import EventHubs, LogAnalyticsWorkspaces
from diagrams.azure.compute import AppServices, ContainerApps, FunctionApps
from diagrams.azure.database import SQLDatabases
from diagrams.azure.identity import EntraManagedIdentities
from diagrams.azure.monitor import ApplicationInsights, Logs as AzLogs, Monitor
from diagrams.azure.network import ExpressrouteCircuits, FrontDoors, PrivateEndpoint
from diagrams.azure.security import AzureSentinel, Defender
from diagrams.elastic.elasticsearch import Alerting, SecuritySettings
from diagrams.gcp.analytics import BigQuery, PubSub
from diagrams.gcp.compute import CloudRun, ComputeEngine, GKE
from diagrams.gcp.network import Armor
from diagrams.gcp.operations import Logging as GcpLogging, Monitoring as GcpMonitoring
from diagrams.gcp.security import Iam as GcpIam, KMS as GcpKms, SecurityCommandCenter
from diagrams.generic.storage import Storage
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.client import Users
from diagrams.onprem.logging import FluentBit
from diagrams.onprem.monitoring import Grafana, Splunk
from diagrams.onprem.vcs import Git

OUT_DIR = Path(__file__).resolve().parent

FONT = "Helvetica"

BASE_GRAPH_ATTR = {
    "fontname": FONT,
    "fontsize": "18",
    "fontcolor": "#0f172a",
    "bgcolor": "#ffffff",
    "pad": "0.55",
    "nodesep": "0.95",
    "ranksep": "1.35",
    "splines": "spline",
    "dpi": "180",
    "labelloc": "t",
    "labeljust": "l",
}

# Keep icons crisp at 1.35" wide inside a 2.60" tall node box so
# (2.60 - 1.35) / 2 = 0.625" of clean gap sits below every square icon for
# 1-to-3 line labels—zero icon-to-text or arrow-to-text collisions.
BASE_NODE_ATTR = {
    "fontname": FONT,
    "fontsize": "10.5",
    "fontcolor": "#0f172a",
    "height": "2.60",
    "width": "1.35",
    "fixedsize": "true",
    "imagescale": "true",
    "margin": "0.12,0.10",
}

BASE_EDGE_ATTR = {
    "fontname": FONT,
    "fontsize": "10",
    "fontcolor": "#334155",
    "minlen": "1.5",
}


def cluster_style(bgcolor: str, border: str, fontcolor: str = "#0f172a") -> dict[str, str]:
    return {
        "fontname": FONT,
        "fontsize": "12",
        "fontcolor": fontcolor,
        "bgcolor": bgcolor,
        "pencolor": border,
        "penwidth": "1.6",
        "style": "rounded,filled",
        "margin": "24",
    }


def pill_label(text: str, fontcolor: str = "#334155", border: str = "#cbd5e1", bg: str = "#ffffff") -> str:
    """Wrap an edge label in a crisp opaque Graphviz HTML pill so lines never cut through text."""
    if not text:
        return ""
    lines = "<BR/>".join(escape(line) for line in text.split("\n"))
    return (
        f'<<TABLE BORDER="1" CELLBORDER="0" CELLSPACING="0" CELLPADDING="4" '
        f'BGCOLOR="{bg}" COLOR="{border}" STYLE="ROUNDED">'
        f'<TR><TD><FONT FACE="{FONT}" POINT-SIZE="9.5" COLOR="{fontcolor}">{lines}</FONT></TD></TR>'
        f"</TABLE>>"
    )


def sec_edge(label: str = "") -> Edge:
    return Edge(
        label=pill_label(label, fontcolor="#065f46", border="#a7f3d0", bg="#f0fdf4"),
        color="#059669",
        penwidth="2.2",
    )


def ops_edge(label: str = "") -> Edge:
    return Edge(
        label=pill_label(label, fontcolor="#475569", border="#cbd5e1", bg="#f8fafc"),
        color="#64748b",
        style="dashed",
        penwidth="1.6",
    )


def fed_edge(label: str = "", color: str = "#2563eb", border: str = "#bfdbfe", bg: str = "#eff6ff") -> Edge:
    return Edge(
        label=pill_label(label, fontcolor=color, border=border, bg=bg),
        color=color,
        penwidth="2.0",
    )


def build_two_stream() -> None:
    with Diagram(
        "Two-Stream SOC-Ready Application Logging Architecture (OWASP + ACSC ISM)",
        filename=str(OUT_DIR / "architecture-two-stream"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=BASE_GRAPH_ATTR,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        users = Users("Agency Users &\nAPI Clients")

        with Cluster("1. Custom Vendor Application", graph_attr=cluster_style("#f8fafc", "#cbd5e1")):
            app = AppServices("App Business Logic\n& Auth Middleware")
            sec_log = SecuritySettings("SecurityLogger Wrapper\nstream='security'\nRedact & CWE-117 Safe")
            ops_log = AzLogs("Operational Logger\nDEBUG, /healthz,\nLatency & Traces")

        with Cluster("2. Normaliser & Privacy Gateway", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e3a8a")):
            router = FluentBit("Bower (Recommended)\nor Fluent Bit / OTel\nDefault-Deny | AU Redact")

        with Cluster("3A. Government SOC SIEM (ISM-1405 / ISM-1988)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            siems = [
                AzureSentinel("Microsoft Sentinel\n(Azure)"),
                SecurityLake("AWS Security Lake\n& Splunk"),
                SecurityCommandCenter("Google SecOps\n(Chronicle)"),
            ]
            soc = Users("SOC Analysts &\nSOAR Detections")

        with Cluster("3B. Operational Telemetry (Never Sent to SIEM)", graph_attr=cluster_style("#f1f5f9", "#94a3b8", "#334155")):
            apm = Grafana("APM / Grafana / Data Lake\n7–30 Days\nLinked via correlation_id")

        users >> Edge(label=pill_label("Trusted Proxy IP\n+ correlation_id"), color="#334155", penwidth="1.8") >> app
        app >> sec_edge("P1/P2 transitions") >> sec_log
        app >> ops_edge("Debug / health") >> ops_log
        sec_log >> sec_edge() >> router
        ops_log >> ops_edge() >> router
        router >> sec_edge("stream == 'security'\n(Never sampled)") >> siems[0]
        router >> sec_edge() >> siems[1]
        router >> sec_edge() >> siems[2]
        router >> ops_edge("stream != 'security'\n(Sampled / rotated)") >> apm
        siems[0] >> sec_edge("Sigma / KQL / SPL\n+ Heartbeat Alert") >> soc
        siems[1] >> sec_edge() >> soc
        siems[2] >> sec_edge() >> soc


def build_signal_vs_noise() -> None:
    with Diagram(
        "Signal-to-Noise Filtering Pipeline (ACSC Priority Logs Discipline)",
        filename=str(OUT_DIR / "signal-vs-noise-funnel"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=BASE_GRAPH_ATTR,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        raw = AppServices("100% Raw App Activity\nHTTP, SQL, Auth, Admin,\nHealth Probes & Assets")

        with Cluster("Diverted to APM / Ops (~90–95% Volume)", graph_attr=cluster_style("#fef2f2", "#fca5a5", "#991b1b")):
            dropped = Grafana("Never Send to SIEM\n/healthz, .js/.css, DEBUG,\nPer-Request Valid JWTs")

        with Cluster("Security Stream Pipeline (stream='security')", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e3a8a")):
            candidates = FluentBit("5–10% Security Events\nAuthn, MFA, Authz 403,\nPrivs, Exports & Config")
            hygiene = SecuritySettings("Hygiene & Flood Gate\nRedact Secrets/PII\nCWE-117 Safe | Dedupe")

        with Cluster("High-Value SOC Signal (1–3% Volume)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            siem = AzureSentinel("SIEM-Ready NDJSON\nScore >= 90/100\nP95 < 2 KB | 0 Leaks")

        raw >> Edge(
            label=pill_label("Drop ~90–95%\n(Saves SIEM $$)", fontcolor="#991b1b", border="#fca5a5", bg="#fef2f2"),
            color="#dc2626",
            style="dashed",
            penwidth="1.8",
        ) >> dropped
        raw >> sec_edge("Keep transitions") >> candidates
        candidates >> fed_edge("Sanitize & cap") >> hygiene
        hygiene >> sec_edge("100% schema valid") >> siem


def build_vendor_lifecycle() -> None:
    graph_attr = {**BASE_GRAPH_ATTR, "ranksep": "1.0"}
    with Diagram(
        "Low-Effort Vendor-to-SOC Lifecycle (Human + AI Coding Agent Workflow)",
        filename=str(OUT_DIR / "vendor-to-soc-lifecycle"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=graph_attr,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        with Cluster("Vendor Engineering + AI Agent", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e3a8a")):
            step1 = Git("1. Install Skills\ninstall-skills.sh\n(4 SKILL.md packs)")
            step2 = AzLogs("2. Audit Repo\nsoc-logging-audit\naudit_repo_logging.py")
            step3 = SecuritySettings("3. Implement\nsoc-logging-implement\nTS / Py / C# / Go")

        with Cluster("Automated CI Quality Gate", graph_attr=cluster_style("#fefce8", "#fcd34d", "#854d0e")):
            step4 = GithubActions("4. Verify in CI\nvalidate_logs.py --strict\nScore >= 90/100")

        with Cluster("Government SOC Onboarding", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            step5 = FluentBit("5. SOC Handoff Pack\ngenerate_soc_handoff.py\nCatalog + KQL/Sigma")
            step6 = Alerting("6. UAT Purple Test\ngenerate_test_events.py\nAlerts + Heartbeat OK")

        step1 >> fed_edge() >> step2 >> fed_edge() >> step3 >> fed_edge() >> step4 >> sec_edge() >> step5 >> sec_edge() >> step6


def build_azure_diagram() -> None:
    with Diagram(
        "Azure & Microsoft Sentinel — Two-Stream SOC Security Logging (Australia East / Southeast)",
        filename=str(OUT_DIR / "cloud-azure-sentinel"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=BASE_GRAPH_ATTR,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        client = Users("External / Agency\nUsers")

        with Cluster("Edge & Client IP", graph_attr=cluster_style("#f0f9ff", "#7dd3fc", "#0c4a6e")):
            fd = FrontDoors("Azure Front Door\n+ WAF\n(X-Azure-ClientIP)")

        with Cluster("Vendor Application Workload (Azure)", graph_attr=cluster_style("#f8fafc", "#cbd5e1")):
            app_svc = AppServices("App Service")
            aks = ContainerApps("Container Apps / AKS")
            funcs = FunctionApps("Azure Functions")
            mi = EntraManagedIdentities("Managed Identity\nMonitoring Metrics\nPublisher (Write-Only)")

        with Cluster("Azure Monitor Ingestion & Pre-Billing Filter", graph_attr=cluster_style("#eff6ff", "#60a5fa", "#1e3a8a")):
            priv = PrivateEndpoint("Private Link\n(AMPLS / DCE)")
            dcr = Monitor("Data Collection Rule\nKQL: where stream\n== 'security'")

        with Cluster("Agency SOC Security Subscription (ISM-1405 / ISM-1815 / ISM-1988)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            law = LogAnalyticsWorkspaces("Log Analytics\nCustomAppSecurity_CL\n(12+ Mo Retention)")
            sentinel = AzureSentinel("Microsoft Sentinel\nStarter KQL Rules &\nHeartbeat Monitor")
            defender = Defender("Defender XDR\nSOC Triage")

        with Cluster("Operational Telemetry (Not Billed to Sentinel)", graph_attr=cluster_style("#f1f5f9", "#94a3b8", "#334155")):
            appinsights = ApplicationInsights("Application Insights /\nBasic & Auxiliary Logs\n(7–30 Days)")

        client >> Edge(color="#0284c7", penwidth="1.8") >> fd >> Edge(color="#0284c7", penwidth="1.8") >> aks
        app_svc >> sec_edge() >> priv
        aks >> sec_edge("stream == 'security'") >> priv
        funcs >> sec_edge() >> priv
        mi >> Edge(label=pill_label("Write-only auth", "#1e40af", "#bfdbfe", "#eff6ff"), color="#2563eb", style="dotted", penwidth="1.8") >> priv
        aks >> ops_edge("stream != 'security'") >> appinsights
        priv >> sec_edge("HTTPS TLS 1.3") >> dcr
        dcr >> sec_edge("Security stream only") >> law
        law >> sec_edge() >> sentinel >> sec_edge() >> defender


def build_aws_diagram() -> None:
    with Diagram(
        "AWS & Amazon Security Lake — Two-Stream SOC Security Logging (ap-southeast-2 / 4)",
        filename=str(OUT_DIR / "cloud-aws-security-lake"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=BASE_GRAPH_ATTR,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        client = Users("External / Agency\nUsers")

        with Cluster("Edge & Client IP", graph_attr=cluster_style("#fff7ed", "#fdba74", "#9a3412")):
            edge_waf = WAF("CloudFront + AWS WAF\n+ ALB (Trusted Hops)")

        with Cluster("Vendor Workload Account (AWS)", graph_attr=cluster_style("#f8fafc", "#cbd5e1")):
            ecs = ECS("ECS Fargate\n(FireLens / Fluent Bit)")
            eks = EKS("EKS\n(Fluent Bit / OTel)")
            lmb = Lambda("AWS Lambda\n(JSON stdout)")
            cw = CloudwatchLogs("CloudWatch Logs\nSub Filter:\n$.stream='security'")
            role = IAMRole("IAM Task Role / IRSA\nWrite-Only PutRecord")
            firehose = KinesisDataFirehose("Amazon Data Firehose\n(OCSF / NDJSON)")

        with Cluster("Isolated Security / Log Archive Account (ISM-1405 / ISM-1815)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            kms = AwsKms("KMS CMK\nEncryption")
            s3 = S3("S3 Archive\nObject Lock WORM\n(12+ Mo Retention)")
            seclake = SecurityLake("Amazon Security Lake\n(OCSF)")
            sechub = SecurityHub("SOC SIEM / OpenSearch\n& Security Hub")

        with Cluster("Operational Logs (Short Retention)", graph_attr=cluster_style("#f1f5f9", "#94a3b8", "#334155")):
            ops_cw = CloudwatchLogs("CloudWatch Ops\n14–30 Days\n(Debug / Health)")

        client >> Edge(color="#ea580c", penwidth="1.8") >> edge_waf >> Edge(color="#ea580c", penwidth="1.8") >> ecs
        ecs >> sec_edge("FireLens direct") >> firehose
        eks >> sec_edge("stream='security'") >> firehose
        lmb >> sec_edge() >> cw
        cw >> sec_edge("$.stream='security'") >> firehose
        cw >> ops_edge("Ops / debug only") >> ops_cw
        role >> Edge(label=pill_label("Write-only", "#1e40af", "#bfdbfe", "#eff6ff"), style="dotted", color="#2563eb", penwidth="1.8") >> firehose
        firehose >> Edge(
            label=pill_label("Cross-account\nwrite-only", "#065f46", "#a7f3d0", "#f0fdf4"),
            color="#059669",
            penwidth="2.2",
            tailport="e",
            headport="n",
        ) >> s3
        kms >> Edge(style="dotted", color="#059669", penwidth="1.8") >> s3
        s3 >> sec_edge() >> seclake >> sec_edge() >> sechub


def build_gcp_diagram() -> None:
    with Diagram(
        "GCP & Google Security Operations (Chronicle) — Two-Stream Logging (australia-southeast1 / 2)",
        filename=str(OUT_DIR / "cloud-gcp-secops"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=BASE_GRAPH_ATTR,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        client = Users("External / Agency\nUsers")

        with Cluster("Edge & Client IP", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e40af")):
            armor = Armor("Cloud Armor +\nExternal App LB\n(2nd-from-last XFF)")

        with Cluster("Vendor Workload Project (GCP)", graph_attr=cluster_style("#f8fafc", "#cbd5e1")):
            crun = CloudRun("Cloud Run")
            gke = GKE("GKE\n(Structured JSON)")
            gce = ComputeEngine("Compute Engine\n(Ops Agent)")
            sa = GcpIam("Workload Identity\nroles/logging.logWriter\n(Write-Only)")
            router = GcpLogging("Cloud Logging Router\nFilter: jsonPayload\n.stream='security'")

        with Cluster("Isolated Security / Logging Project (ISM-1405 / ISM-1815)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            pubsub = PubSub("Pub/Sub Topic\n+ Dead-Letter Topic")
            kms = GcpKms("Cloud KMS\nCMEK")
            bucket = GcpLogging("Locked Log Bucket\n400d Retention Lock\n(--locked)")
            secops = SecurityCommandCenter("Google SecOps\n(Chronicle SIEM)\nUDM + YARA-L")
            bq = BigQuery("BigQuery\nThreat Hunting")

        with Cluster("Operational Telemetry", graph_attr=cluster_style("#f1f5f9", "#94a3b8", "#334155")):
            ops_mon = GcpMonitoring("_Default Bucket (30d)\n+ Cloud Monitoring\n(/healthz excluded)")

        client >> Edge(color="#2563eb", penwidth="1.8") >> armor >> Edge(color="#2563eb", penwidth="1.8") >> crun
        crun >> sec_edge() >> router
        gke >> sec_edge() >> router
        gce >> sec_edge() >> router
        sa >> Edge(label=pill_label("Write-only", "#1e40af", "#bfdbfe", "#eff6ff"), style="dotted", color="#2563eb", penwidth="1.8") >> router
        router >> sec_edge("jsonPayload.stream\n== 'security'") >> pubsub
        router >> sec_edge("Immutable archive") >> bucket
        kms >> Edge(style="dotted", color="#059669", penwidth="1.8") >> bucket
        router >> ops_edge("Ops / non-security") >> ops_mon
        pubsub >> sec_edge() >> secops
        pubsub >> fed_edge("Optional hunt export") >> bq


def build_cross_cloud_federation() -> None:
    graph_attr = {**BASE_GRAPH_ATTR, "ranksep": "1.65", "nodesep": "1.05"}
    with Diagram(
        "Cross-Cloud & Hybrid Log Federation (Zero Static Keys — Filter stream='security' Before Egress)",
        filename=str(OUT_DIR / "cross-cloud-log-federation"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=graph_attr,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        with Cluster("AWS Source (Filtered stream='security')", graph_attr=cluster_style("#fff7ed", "#fdba74", "#9a3412")):
            aws_fh = KinesisDataFirehose("AWS Firehose")
            aws_s3_sqs = SQS("S3 + SQS\n(IAM Role OIDC)")

        with Cluster("GCP Source (Filtered stream='security')", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e40af")):
            gcp_sink = GcpLogging("Cloud Logging Sink")
            gcp_ps = PubSub("Pub/Sub\n(Workload Identity)")

        with Cluster("Azure Source (Filtered stream='security')", graph_attr=cluster_style("#f0f9ff", "#38bdf8", "#0c4a6e")):
            az_dcr = Monitor("Azure Monitor DCR")
            az_eh = EventHubs("Event Hubs\n(Entra WIF)")

        with Cluster("On-Prem / Private Gov Network", graph_attr=cluster_style("#f8fafc", "#94a3b8", "#334155")):
            onprem_fb = FluentBit("Bower / OTel / Fluent Bit\nTamper Ledger + mTLS")
            link = ExpressrouteCircuits("ExpressRoute /\nDirect Connect /\nInterconnect")

        with Cluster("Target Agency SOC SIEM Platforms", graph_attr=cluster_style("#ecfdf5", "#10b981", "#065f46")):
            t_sentinel = AzureSentinel("Microsoft Sentinel\n(Bower / Azure CCF / DCR)")
            t_secops = SecurityCommandCenter("Google SecOps\n(Chronicle Native Feeds)")
            t_seclake = SecurityLake("AWS Security Lake\n& Splunk HEC (Bower)")

        aws_fh >> Edge(color="#ea580c", penwidth="2.0") >> aws_s3_sqs
        gcp_sink >> Edge(color="#2563eb", penwidth="2.0") >> gcp_ps
        az_dcr >> Edge(color="#0284c7", penwidth="2.0") >> az_eh
        onprem_fb >> Edge(color="#475569", penwidth="2.0") >> link

        aws_s3_sqs >> sec_edge("OIDC S3/SQS CCF") >> t_sentinel
        aws_s3_sqs >> fed_edge("AssumeRole S3 Feed", "#1d4ed8", "#bfdbfe", "#eff6ff") >> t_secops

        gcp_ps >> sec_edge("WIF Pub/Sub CCF") >> t_sentinel
        gcp_ps >> fed_edge("OIDC -> Firehose", "#c2410c", "#fed7aa", "#fff7ed") >> t_seclake

        az_eh >> fed_edge("Native EH Feed", "#1d4ed8", "#bfdbfe", "#eff6ff") >> t_secops
        az_eh >> fed_edge("STS WIF -> Firehose", "#c2410c", "#fed7aa", "#fff7ed") >> t_seclake

        link >> sec_edge("Private Link / TLS 1.3") >> t_sentinel
        link >> ops_edge("Private Link") >> t_seclake


def build_bower_diagram() -> None:
    graph_attr = {**BASE_GRAPH_ATTR, "ranksep": "1.55", "nodesep": "1.0"}
    with Diagram(
        "Bower Open-Source Privacy Gateway & Normaliser (Collect -> Select -> Arrange -> Deliver -> Prove)",
        filename=str(OUT_DIR / "bower-privacy-gateway"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=graph_attr,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        with Cluster("1. Collect (Multi-Cloud, Custom & Legacy)", graph_attr=cluster_style("#f8fafc", "#cbd5e1")):
            src_app = AppServices("Custom Apps\n(Bower SDK / NDJSON\n+ Docker Sidecar)")
            src_sql = SQLDatabases("Legacy SQL Server\nAudit Tables\n(ReadOnly EF Adapter)")
            src_aws = SQS("AWS Security Signal\nGuardDuty / CloudTrail\n(IAM Role — No Keys)")
            src_gcp = PubSub("GCP Security Signal\nSCC / Admin Audit\n(WIF — Key Files Refused)")

        with Cluster("2. Select & Arrange (Host-Side Before Egress)", graph_attr=cluster_style("#eff6ff", "#60a5fa", "#1e3a8a")):
            privacy = SecuritySettings("AU Privacy Engine\nTFN, Medicare, IHI,\nABN, CRN & Secrets")
            policy = FluentBit("Default-Deny Pack\nSchema + Value Policy\nFlood Suppression")
            queue = Storage("SQLite WAL Queue\nHash-Chained Ledger\nDead-Letter & Replay")

        with Cluster("3. Deliver & Prove (ACSC ISM & Essential Eight)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            out_sentinel = AzureSentinel("Microsoft Sentinel\nLogs Ingestion API / DCR\nor AMA JSONL Spool")
            out_s3 = S3("AWS S3 Output\n(Default Cred Chain)")
            out_hec = Splunk("Splunk HEC /\nHTTP NDJSON")
            prove = Alerting("bower evidence run\nLive Sentinel Canary KQL\nSigned ISM / E8 Bundle")

        src_app >> Edge(color="#059669", penwidth="2.2", headport="w") >> privacy
        src_sql >> Edge(color="#059669", penwidth="2.2", headport="w") >> privacy
        src_aws >> Edge(
            label=pill_label("bower-cloud", "#c2410c", "#fed7aa", "#fff7ed"),
            color="#c2410c",
            penwidth="2.0",
            headport="w",
        ) >> privacy
        src_gcp >> Edge(
            label=pill_label("bower-cloud", "#1d4ed8", "#bfdbfe", "#eff6ff"),
            color="#1d4ed8",
            penwidth="2.0",
            headport="w",
        ) >> privacy

        privacy >> sec_edge("Redacted +\nsensitive_data_detected") >> policy
        policy >> sec_edge("Approved events\nonly") >> queue

        queue >> sec_edge("DCE / DCR or AMA") >> out_sentinel
        queue >> fed_edge("BOWER_OUTPUT=s3", "#c2410c", "#fed7aa", "#fff7ed") >> out_s3
        queue >> ops_edge("BOWER_OUTPUT=http") >> out_hec
        out_sentinel >> sec_edge("Read-only\nKQL proof") >> prove


def main() -> int:
    build_two_stream()
    build_signal_vs_noise()
    build_vendor_lifecycle()
    build_azure_diagram()
    build_aws_diagram()
    build_gcp_diagram()
    build_cross_cloud_federation()
    build_bower_diagram()
    print(f"Generated 8 PNG diagrams cleanly in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
