package dev.jusso.soclogging;

import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * Minimal, zero-external-dependency SOC-ready SecurityAuditLogger (Java 17+).
 * Aligns with OWASP Logging Vocabulary / ASVS V16 and ACSC ISM System Monitoring.
 * Emits single-line NDJSON (`stream: "security"`) with automatic secret/PII
 * redaction, CWE-117 control-character stripping, UTC ISO-8601 timestamps, and
 * periodic pipeline heartbeats.
 */
public final class SecurityAuditLogger {

    private static final DateTimeFormatter UTC_ISO =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private static final Pattern SENSITIVE_KEY = Pattern.compile(
            "(pass(word|wd|phrase)?|secret|token|authorization|cookie|api[_-]?key|private[_-]?key|"
                    + "tfn|medicare|ssn|credit[_-]?card|card[_-]?number|cvv|pin|otp)",
            Pattern.CASE_INSENSITIVE);

    private static final List<Pattern> SECRET_VALUES = List.of(
            Pattern.compile("Bearer\\s+[A-Za-z0-9\\-._~+/]+=*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b"),
            Pattern.compile("(password|passwd|pwd|secret|api_key|token)\\s*[:=]\\s*\\S+", Pattern.CASE_INSENSITIVE));

    private static final Pattern ANSI = Pattern.compile("\\u001B\\[[0-?]*[ -/]*[@-~]");
    private static final Pattern CONTROL = Pattern.compile("[\\x00-\\x1F\\x7F]+");

    private final Map<String, Object> app;
    private final PrintStream out;
    private final AtomicLong emittedSinceHeartbeat = new AtomicLong(0);

    public SecurityAuditLogger(String appId, String appName, String environment, String version, String component) {
        this(appId, appName, environment, version, component, System.out);
    }

    public SecurityAuditLogger(
            String appId, String appName, String environment, String version, String component, PrintStream out) {
        this.app = new LinkedHashMap<>();
        this.app.put("id", sanitize(appId, 64));
        this.app.put("name", sanitize(appName, 120));
        if (component != null && !component.isBlank()) {
            this.app.put("component", sanitize(component, 80));
        }
        this.app.put("environment", sanitize(environment, 16));
        this.app.put("version", sanitize(version, 64));
        this.app.put("host", resolveHostname());
        this.out = out;
    }

    public static String sanitize(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        String clean = ANSI.matcher(value).replaceAll("");
        clean = CONTROL.matcher(clean).replaceAll(" ");
        for (Pattern p : SECRET_VALUES) {
            clean = p.matcher(clean).replaceAll("[REDACTED]");
        }
        clean = clean.trim();
        return clean.length() > maxLength ? clean.substring(0, maxLength) : clean;
    }

    public static String hashSessionId(String rawSessionId, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest((salt + ":" + rawSessionId).getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder("sha256:");
            for (int i = 0; i < 16; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public String emit(
            String event,
            String category,
            String severity,
            String outcome,
            Map<String, Object> actor,
            Map<String, Object> source,
            Map<String, Object> target,
            String correlationId,
            String reason,
            String message,
            Map<String, Object> details) {

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("schema_version", "1.0.0");
        record.put("timestamp", UTC_ISO.format(Instant.now()));
        record.put("stream", "security");
        record.put("event", sanitize(event, 80));
        if (category != null && !category.isBlank()) {
            record.put("category", sanitize(category, 40));
        }
        record.put("severity", severity);
        record.put("outcome", outcome);
        record.put("app", app);
        record.put("actor", redactMap(actor));
        record.put("source", redactMap(source));
        if (target != null && !target.isEmpty()) {
            record.put("target", redactMap(target));
        }
        String corr = (correlationId == null || correlationId.isBlank())
                ? "trace-" + UUID.randomUUID()
                : sanitize(correlationId, 128);
        record.put("correlation_id", corr);
        if (reason != null && !reason.isBlank()) {
            record.put("reason", sanitize(reason, 128));
        }
        record.put("message", sanitize(message, 512));
        if (details != null && !details.isEmpty()) {
            record.put("details", redactMap(details));
        }

        String line = toJson(record);
        emittedSinceHeartbeat.incrementAndGet();
        out.println(line);
        return line;
    }

    public String emitHeartbeat(int intervalSeconds, long droppedEvents) {
        long count = emittedSinceHeartbeat.getAndSet(0);
        return emit(
                "sys_logging_heartbeat",
                "system",
                "INFO",
                "success",
                Map.of("type", "system", "id", "system:audit-heartbeat"),
                Map.of("ip", "127.0.0.1"),
                null,
                null,
                null,
                "Security logging pipeline heartbeat OK",
                Map.of(
                        "interval_seconds", intervalSeconds,
                        "events_emitted_since_last", count,
                        "dropped_events", droppedEvents));
    }

    private static Map<String, Object> redactMap(Map<String, Object> input) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (input == null) {
            return out;
        }
        int count = 0;
        for (Map.Entry<String, Object> entry : input.entrySet()) {
            if (count++ >= 25) {
                break;
            }
            String k = entry.getKey();
            Object v = entry.getValue();
            if (SENSITIVE_KEY.matcher(k).find()) {
                out.put(k, "[REDACTED]");
            } else if (v instanceof String s) {
                out.put(k, sanitize(s, 512));
            } else if (v instanceof Map<?, ?> nested) {
                Map<String, Object> sub = new LinkedHashMap<>();
                for (Map.Entry<?, ?> ne : nested.entrySet()) {
                    sub.put(String.valueOf(ne.getKey()), ne.getValue());
                }
                out.put(k, redactMap(sub));
            } else {
                out.put(k, v);
            }
        }
        return out;
    }

    private static String resolveHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown-host";
        }
    }

    private static String toJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String s) {
            return quoteJson(s);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return value.toString();
        }
        if (value instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(toJson(list.get(i)));
            }
            return sb.append(']').toString();
        }
        if (value instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(quoteJson(String.valueOf(e.getKey()))).append(':').append(toJson(e.getValue()));
            }
            return sb.append('}').toString();
        }
        return quoteJson(sanitize(value.toString(), 512));
    }

    private static String quoteJson(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
