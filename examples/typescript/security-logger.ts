/**
 * Minimal, zero-dependency SOC-ready SecurityLogger (TypeScript / Node 18+).
 * Aligns with OWASP Logging Vocabulary / ASVS V16 and ACSC ISM System Monitoring.
 *
 * Emits single-line JSON (NDJSON) with `stream: "security"`, automatic secret/PII
 * redaction, CWE-117 control-character stripping, and UTC ISO-8601 timestamps.
 */

import { createHash, randomUUID } from "node:crypto";
import { hostname } from "node:os";

export type SecuritySeverity = "INFO" | "WARN" | "HIGH" | "CRITICAL";
export type SecurityOutcome = "success" | "failure" | "blocked" | "unknown";
export type EnvironmentName = "prod" | "staging" | "uat" | "test" | "dev";

export interface AppMetadata {
  id: string;
  name: string;
  component?: string;
  environment: EnvironmentName;
  version: string;
  host?: string;
}

export interface SecurityActor {
  type: "user" | "admin" | "service" | "api_client" | "anonymous" | "system";
  id: string;
  username?: string;
  roles?: string[];
  tenant_id?: string;
  session_id_hash?: string;
  impersonated_by?: string;
}

export interface SecuritySource {
  ip: string;
  port?: number;
  user_agent?: string;
  asn?: number;
  geo_country?: string;
}

export interface SecurityTarget {
  type?: string;
  id?: string;
  name?: string;
  classification?:
    | "UNOFFICIAL"
    | "OFFICIAL"
    | "OFFICIAL:Sensitive"
    | "PROTECTED"
    | "PUBLIC"
    | "INTERNAL"
    | "CONFIDENTIAL"
    | "RESTRICTED";
}

export interface SecurityHttp {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
  route?: string;
  status_code?: number;
}

export interface SecurityEventInput {
  event: string;
  category?: string;
  severity: SecuritySeverity;
  outcome: SecurityOutcome;
  actor: SecurityActor;
  source: SecuritySource;
  target?: SecurityTarget;
  http?: SecurityHttp;
  correlation_id?: string;
  reason?: string;
  message: string;
  details?: Record<string, unknown>;
}

const SENSITIVE_KEY_PATTERN =
  /(pass(word|wd|phrase)?|secret|token|authorization|cookie|api[_-]?key|private[_-]?key|tfn|medicare|ssn|credit[_-]?card|card[_-]?number|cvv|pin|otp)/i;

const SECRET_VALUE_PATTERNS: RegExp[] = [
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
  /(password|passwd|pwd|secret|api_key|token)\s*[:=]\s*\S+/gi,
];

const ANSI_PATTERN = /\x1B\[[0-?]*[ -/]*[@-~]/g;
const CONTROL_CHAR_PATTERN = /[\x00-\x1F\x7F]+/g;

export function sanitizeString(value: string, maxLength = 512): string {
  let clean = value.replace(ANSI_PATTERN, "").replace(CONTROL_CHAR_PATTERN, " ");
  for (const pattern of SECRET_VALUE_PATTERNS) {
    clean = clean.replace(pattern, "[REDACTED]");
  }
  clean = clean.trim();
  return clean.length > maxLength ? clean.slice(0, maxLength) : clean;
}

export function redactObject(value: unknown, depth = 0): unknown {
  if (depth > 5) return "[TRUNCATED]";
  if (typeof value === "string") return sanitizeString(value);
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 25).map((item) => redactObject(item, depth + 1));
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value).slice(0, 25)) {
      if (SENSITIVE_KEY_PATTERN.test(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = redactObject(v, depth + 1);
      }
    }
    return out;
  }
  return "[UNSUPPORTED]";
}

export function hashSessionId(rawSessionId: string, salt = ""): string {
  const digest = createHash("sha256")
    .update(`${salt}:${rawSessionId}`)
    .digest("hex")
    .slice(0, 32);
  return `sha256:${digest}`;
}

export class SecurityLogger {
  private readonly app: AppMetadata;
  private readonly sink: (line: string) => void;
  private emittedSinceHeartbeat = 0;

  constructor(app: AppMetadata, sink: (line: string) => void = (line) => process.stdout.write(`${line}\n`)) {
    this.app = { ...app, host: app.host ?? hostname() };
    this.sink = sink;
  }

  emit(input: SecurityEventInput): string {
    const record: Record<string, unknown> = {
      schema_version: "1.0.0",
      timestamp: new Date().toISOString(),
      stream: "security",
      event: sanitizeString(input.event, 80),
      ...(input.category ? { category: input.category } : {}),
      severity: input.severity,
      outcome: input.outcome,
      app: this.app,
      actor: redactObject(input.actor),
      source: redactObject(input.source),
      ...(input.target ? { target: redactObject(input.target) } : {}),
      ...(input.http ? { http: redactObject(input.http) } : {}),
      correlation_id: sanitizeString(input.correlation_id ?? `trace-${randomUUID()}`, 128),
      ...(input.reason ? { reason: sanitizeString(input.reason, 128) } : {}),
      message: sanitizeString(input.message, 512),
      ...(input.details ? { details: redactObject(input.details) } : {}),
    };

    const line = JSON.stringify(record);
    this.emittedSinceHeartbeat += 1;
    this.sink(line);
    return line;
  }

  emitHeartbeat(intervalSeconds = 900, droppedEvents = 0): string {
    const count = this.emittedSinceHeartbeat;
    this.emittedSinceHeartbeat = 0;
    return this.emit({
      event: "sys_logging_heartbeat",
      category: "system",
      severity: "INFO",
      outcome: "success",
      actor: { type: "system", id: "system:audit-heartbeat" },
      source: { ip: "127.0.0.1" },
      message: "Security logging pipeline heartbeat OK",
      details: {
        interval_seconds: intervalSeconds,
        events_emitted_since_last: count,
        dropped_events: droppedEvents,
      },
    });
  }
}
