#!/usr/bin/env python3
"""Generate all architecture & cloud diagrams using the Python `diagrams` library.

Uses one consistent font family (`Helvetica`) and official Azure, AWS, GCP, and
OSS/On-Prem icons across every diagram.

Requirements:
    - Graphviz (`brew install graphviz` or `apt-get install graphviz`)
    - Python `diagrams` (`uv run --with diagrams python3 diagrams/generate_diagrams.py`)
"""

from __future__ import annotations

from pathlib import Path

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.analytics import KinesisDataFirehose
from diagrams.aws.compute import ECS, EKS, Lambda
from diagrams.aws.integration import SQS
from diagrams.aws.management import CloudwatchLogs
from diagrams.aws.network import DirectConnect
from diagrams.aws.security import IAMRole, KMS as AwsKms, SecurityHub, SecurityLake, WAF
from diagrams.aws.storage import S3
from diagrams.azure.analytics import EventHubs, LogAnalyticsWorkspaces
from diagrams.azure.compute import AppServices, ContainerApps, FunctionApps
from diagrams.azure.identity import EntraManagedIdentities
from diagrams.azure.monitor import ApplicationInsights, Monitor
from diagrams.azure.network import ExpressrouteCircuits, FrontDoors, PrivateEndpoint
from diagrams.azure.security import AzureSentinel, Defender
from diagrams.gcp.analytics import BigQuery, PubSub
from diagrams.gcp.compute import CloudRun, ComputeEngine, GKE
from diagrams.gcp.network import Armor
from diagrams.gcp.operations import Logging as GcpLogging, Monitoring as GcpMonitoring
from diagrams.gcp.security import Iam as GcpIam, KMS as GcpKms, SecurityCommandCenter
from diagrams.generic.blank import Blank
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.client import Users
from diagrams.onprem.compute import Server
from diagrams.onprem.logging import FluentBit, Loki
from diagrams.onprem.security import Vault
from diagrams.onprem.vcs import Git

OUT_DIR = Path(__file__).resolve().parent

FONT = "Helvetica"

BASE_GRAPH_ATTR = {
    "fontname": FONT,
    "fontsize": "18",
    "fontcolor": "#0f172a",
    "bgcolor": "#ffffff",
    "pad": "0.5",
    "nodesep": "0.75",
    "ranksep": "1.05",
    "splines": "spline",
    "dpi": "180",
    "labelloc": "t",
    "labeljust": "l",
}

BASE_NODE_ATTR = {
    "fontname": FONT,
    "fontsize": "11",
    "fontcolor": "#0f172a",
    "margin": "0.18,0.14",
}

BASE_EDGE_ATTR = {
    "fontname": FONT,
    "fontsize": "10",
    "fontcolor": "#334155",
    "minlen": "1.3",
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
        "margin": "20",
    }


def sec_edge(label: str = "") -> Edge:
    return Edge(label=label, color="#059669", penwidth="2.2", fontname=FONT, fontsize="10", fontcolor="#065f46")


def ops_edge(label: str = "") -> Edge:
    return Edge(label=label, color="#64748b", style="dashed", penwidth="1.6", fontname=FONT, fontsize="10", fontcolor="#475569")


def fed_edge(label: str = "", color: str = "#2563eb") -> Edge:
    return Edge(label=label, color=color, penwidth="2.0", fontname=FONT, fontsize="10", fontcolor=color)


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
            app = Server("App Logic &\nAuth Middleware")
            sec_log = Vault("SecurityLogger Wrapper\nstream='security' | Redact\nCWE-117 Safe | UTC Z")
            ops_log = Server("Operational Logger\nDEBUG | /healthz | Perf")

        with Cluster("2. Collector & Stream Router", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e3a8a")):
            router = FluentBit("Fluent Bit / OTel\nFilter on stream field\nWrite-Only Sink Creds")

        with Cluster("3A. Government SOC SIEM (ISM-1405 / ISM-1988)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            sentinel = AzureSentinel("Microsoft Sentinel /\nSplunk / SecOps\n12+ Mo Searchable")
            soc = Users("SOC Analysts &\nSOAR Detections")

        with Cluster("3B. Operational Telemetry (Never Sent to SIEM)", graph_attr=cluster_style("#f1f5f9", "#94a3b8", "#334155")):
            apm = Loki("APM / Loki / Data Lake\n7–30 Days | Linked via\ncorrelation_id")

        users >> Edge(label="Trusted Proxy IP\n+ correlation_id", color="#334155") >> app
        app >> sec_edge("P1/P2 transitions") >> sec_log
        app >> ops_edge("Debug / health") >> ops_log
        sec_log >> sec_edge() >> router
        ops_log >> ops_edge() >> router
        router >> sec_edge("stream == 'security'\n(Never sampled)") >> sentinel
        router >> ops_edge("stream != 'security'\n(Sampled / rotated)") >> apm
        sentinel >> sec_edge("Sigma / KQL / SPL\n+ Heartbeat Alert") >> soc


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
        raw = Server("100% Raw App Activity\nHTTP, SQL, Auth, Admin,\nHealth Probes, Assets")

        with Cluster("Diverted to APM / Ops (~90–95% Volume)", graph_attr=cluster_style("#fef2f2", "#fca5a5", "#991b1b")):
            dropped = Loki("Never Send to SIEM\n/healthz, .js/.css, DEBUG,\nPer-Request Valid JWTs")

        with Cluster("Security Stream Pipeline (stream='security')", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e3a8a")):
            candidates = FluentBit("5–10% Security Transitions\nAuthn, MFA, Authz 403,\nPrivs, Exports, Config")
            hygiene = Vault("Hygiene & Flood Gate\nRedact Secrets/PII\nStrip CWE-117 | Dedupe")

        with Cluster("High-Value SOC Signal (1–3% Volume)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            siem = AzureSentinel("SIEM-Ready NDJSON\nScore >= 90/100\nP95 < 2 KB | 0 Leaks")

        raw >> Edge(label="Drop ~90–95%\n(Saves SIEM $$)", color="#dc2626", style="dashed", penwidth="1.8", fontcolor="#991b1b") >> dropped
        raw >> sec_edge("Keep transitions") >> candidates
        candidates >> fed_edge("Sanitize & cap") >> hygiene
        hygiene >> sec_edge("100% schema valid") >> siem


def build_vendor_lifecycle() -> None:
    with Diagram(
        "Low-Effort Vendor-to-SOC Lifecycle (Human + AI Coding Agent Workflow)",
        filename=str(OUT_DIR / "vendor-to-soc-lifecycle"),
        outformat="png",
        show=False,
        direction="LR",
        graph_attr=BASE_GRAPH_ATTR,
        node_attr=BASE_NODE_ATTR,
        edge_attr=BASE_EDGE_ATTR,
    ):
        with Cluster("Vendor Engineering + AI Agent", graph_attr=cluster_style("#eff6ff", "#93c5fd", "#1e3a8a")):
            step1 = Git("1. Install Skills\ninstall-skills.sh\n(4 SKILL.md packs)")
            step2 = Server("2. Audit Repo\nsoc-logging-audit\naudit_repo_logging.py")
            step3 = Vault("3. Implement\nsoc-logging-implement\nTS / Py / C# / Go")

        with Cluster("Automated CI Quality Gate", graph_attr=cluster_style("#fefce8", "#fcd34d", "#854d0e")):
            step4 = GithubActions("4. Verify in CI\nvalidate_logs.py --strict\nscore >= 90/100")

        with Cluster("Government SOC Onboarding", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            step5 = FluentBit("5. SOC Handoff Pack\ngenerate_soc_handoff.py\nCatalog + KQL/Sigma")
            step6 = AzureSentinel("6. UAT Purple Test\ngenerate_test_events.py\nAlerts + Heartbeat OK")

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

        client >> Edge(color="#0284c7") >> fd >> Edge(color="#0284c7") >> aks
        app_svc >> sec_edge() >> priv
        aks >> sec_edge("stream == 'security'") >> priv
        funcs >> sec_edge() >> priv
        mi >> Edge(label="Write-only auth", color="#2563eb", style="dotted") >> priv
        aks >> ops_edge("stream != 'security'") >> appinsights
        priv >> sec_edge("HTTPS TLS 1.3") >> dcr
        dcr >> sec_edge("Filtered security\nevents only") >> law
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
            firehose = KinesisDataFirehose("Amazon Data\nFirehose\n(OCSF / NDJSON)")

        with Cluster("Isolated Security / Log Archive Account (ISM-1405 / ISM-1815)", graph_attr=cluster_style("#ecfdf5", "#34d399", "#065f46")):
            kms = AwsKms("KMS CMK\nEncryption")
            s3 = S3("S3 Archive\nObject Lock WORM\n(12+ Mo Retention)")
            seclake = SecurityLake("Amazon Security\nLake (OCSF)")
            sechub = SecurityHub("SOC SIEM / OpenSearch\n& Security Hub")

        with Cluster("Operational Logs (Short Retention)", graph_attr=cluster_style("#f1f5f9", "#94a3b8", "#334155")):
            ops_cw = CloudwatchLogs("CloudWatch Ops\n14–30 Days\n(Debug / Health)")

        client >> Edge(color="#ea580c") >> edge_waf >> Edge(color="#ea580c") >> ecs
        ecs >> sec_edge("FireLens direct") >> firehose
        eks >> sec_edge("stream='security'") >> firehose
        lmb >> sec_edge() >> cw
        cw >> sec_edge("$.stream='security'") >> firehose
        cw >> ops_edge("Ops / debug only") >> ops_cw
        role >> Edge(label="Write-only", style="dotted", color="#2563eb") >> firehose
        firehose >> sec_edge("Cross-account\nwrite-only") >> s3
        kms >> Edge(style="dotted", color="#059669") >> s3
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

        client >> Edge(color="#2563eb") >> armor >> Edge(color="#2563eb") >> crun
        crun >> sec_edge() >> router
        gke >> sec_edge() >> router
        gce >> sec_edge() >> router
        sa >> Edge(label="Write-only", style="dotted", color="#2563eb") >> router
        router >> sec_edge("jsonPayload.stream\n== 'security'") >> pubsub
        router >> sec_edge("Immutable archive") >> bucket
        kms >> Edge(style="dotted", color="#059669") >> bucket
        router >> ops_edge("Ops / non-security") >> ops_mon
        pubsub >> sec_edge() >> secops
        pubsub >> fed_edge("Optional hunt export") >> bq


def build_cross_cloud_federation() -> None:
    graph_attr = {**BASE_GRAPH_ATTR, "ranksep": "1.35", "nodesep": "0.85"}
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
            onprem_fb = FluentBit("OTel / Fluent Bit\nDisk Buffer + mTLS")
            link = ExpressrouteCircuits("ExpressRoute /\nDirect Connect /\nInterconnect")

        with Cluster("Target Agency SOC SIEM Platforms", graph_attr=cluster_style("#ecfdf5", "#10b981", "#065f46")):
            t_sentinel = AzureSentinel("Microsoft Sentinel\n(Azure CCF / DCR /\nBower)")
            t_secops = SecurityCommandCenter("Google SecOps\n(Chronicle Native Feeds)")
            t_seclake = SecurityLake("AWS Security Lake\n& Splunk / OpenSearch")

        aws_fh >> Edge(color="#ea580c", penwidth="2.0") >> aws_s3_sqs
        gcp_sink >> Edge(color="#2563eb", penwidth="2.0") >> gcp_ps
        az_dcr >> Edge(color="#0284c7", penwidth="2.0") >> az_eh
        onprem_fb >> Edge(color="#475569", penwidth="2.0") >> link

        # Clean federation paths with zero static secrets
        aws_s3_sqs >> sec_edge("OIDC S3/SQS CCF") >> t_sentinel
        aws_s3_sqs >> fed_edge("AssumeRole S3 Feed", "#2563eb") >> t_secops

        gcp_ps >> sec_edge("WIF Pub/Sub CCF") >> t_sentinel
        gcp_ps >> fed_edge("OIDC -> Firehose", "#ea580c") >> t_seclake

        az_eh >> fed_edge("Native EH Feed", "#2563eb") >> t_secops
        az_eh >> fed_edge("STS WIF -> Firehose", "#ea580c") >> t_seclake

        link >> sec_edge("Private Link / TLS 1.3") >> t_sentinel
        link >> ops_edge("Private Link") >> t_seclake


def main() -> int:
    build_two_stream()
    build_signal_vs_noise()
    build_vendor_lifecycle()
    build_azure_diagram()
    build_aws_diagram()
    build_gcp_diagram()
    build_cross_cloud_federation()
    print(f"Generated 7 PNG diagrams cleanly in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
