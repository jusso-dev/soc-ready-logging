// Minimal, zero-external-dependency SOC-ready SecurityAuditLogger (.NET 8/9/10).
// Aligns with OWASP Logging Vocabulary / ASVS V16 and ACSC ISM System Monitoring.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SocReadyLogging;

public sealed record AppMetadata(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("environment")] string Environment,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("component")] string? Component = null,
    [property: JsonPropertyName("host")] string? Host = null
);

public sealed record SecurityActor(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("username")] string? Username = null,
    [property: JsonPropertyName("roles")] IReadOnlyList<string>? Roles = null,
    [property: JsonPropertyName("tenant_id")] string? TenantId = null,
    [property: JsonPropertyName("session_id_hash")] string? SessionIdHash = null,
    [property: JsonPropertyName("impersonated_by")] string? ImpersonatedBy = null
);

public sealed record SecuritySource(
    [property: JsonPropertyName("ip")] string Ip,
    [property: JsonPropertyName("user_agent")] string? UserAgent = null,
    [property: JsonPropertyName("geo_country")] string? GeoCountry = null
);

public sealed record SecurityTarget(
    [property: JsonPropertyName("type")] string? Type = null,
    [property: JsonPropertyName("id")] string? Id = null,
    [property: JsonPropertyName("name")] string? Name = null,
    [property: JsonPropertyName("classification")] string? Classification = null
);

public sealed record SecurityHttp(
    [property: JsonPropertyName("method")] string? Method = null,
    [property: JsonPropertyName("route")] string? Route = null,
    [property: JsonPropertyName("status_code")] int? StatusCode = null
);

public sealed class SecurityAuditLogger
{
    private static readonly Regex SensitiveKeyRegex = new(
        @"(pass(word|wd|phrase)?|secret|token|authorization|cookie|api[_-]?key|private[_-]?key|tfn|medicare|ssn|credit[_-]?card|cvv|pin|otp)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex[] SecretValueRegexes =
    {
        new(@"Bearer\s+[A-Za-z0-9\-._~+/]+=*", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", RegexOptions.Compiled),
        new(@"(password|passwd|pwd|secret|api_key|token)\s*[:=]\s*\S+", RegexOptions.IgnoreCase | RegexOptions.Compiled)
    };

    private static readonly Regex AnsiRegex = new(@"\x1B\[[0-?]*[ -/]*[@-~]", RegexOptions.Compiled);
    private static readonly Regex ControlRegex = new(@"[\x00-\x1F\x7F]+", RegexOptions.Compiled);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    private readonly AppMetadata _app;
    private readonly TextWriter _writer;
    private long _emittedSinceHeartbeat;

    public SecurityAuditLogger(AppMetadata app, TextWriter? writer = null)
    {
        _app = app with { Host = app.Host ?? Environment.MachineName };
        _writer = writer ?? Console.Out;
    }

    public static string Sanitize(string input, int maxLength = 512)
    {
        var clean = AnsiRegex.Replace(input, string.Empty);
        clean = ControlRegex.Replace(clean, " ");
        foreach (var regex in SecretValueRegexes)
        {
            clean = regex.Replace(clean, "[REDACTED]");
        }
        clean = clean.Trim();
        return clean.Length > maxLength ? clean[..maxLength] : clean;
    }

    public static string HashSessionId(string rawSessionId, string salt = "")
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{salt}:{rawSessionId}"));
        var hex = Convert.ToHexString(bytes).ToLowerInvariant()[..32];
        return $"sha256:{hex}";
    }

    public string Emit(
        string eventName,
        string severity,
        string outcome,
        SecurityActor actor,
        SecuritySource source,
        string message,
        string? category = null,
        SecurityTarget? target = null,
        SecurityHttp? http = null,
        string? correlationId = null,
        string? reason = null,
        IReadOnlyDictionary<string, object?>? details = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["schema_version"] = "1.0.0",
            ["timestamp"] = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            ["stream"] = "security",
            ["event"] = Sanitize(eventName, 80),
            ["severity"] = severity,
            ["outcome"] = outcome,
            ["app"] = _app,
            ["actor"] = actor with
            {
                Id = Sanitize(actor.Id, 128),
                Username = actor.Username is null ? null : Sanitize(actor.Username, 128)
            },
            ["source"] = source with
            {
                Ip = Sanitize(source.Ip, 45),
                UserAgent = source.UserAgent is null ? null : Sanitize(source.UserAgent, 512)
            },
            ["correlation_id"] = Sanitize(correlationId ?? $"trace-{Guid.NewGuid():N}", 128),
            ["message"] = Sanitize(message, 512)
        };

        if (category is not null) payload["category"] = category;
        if (target is not null) payload["target"] = target;
        if (http is not null) payload["http"] = http;
        if (reason is not null) payload["reason"] = Sanitize(reason, 128);
        if (details is not null) payload["details"] = RedactDictionary(details);

        var line = JsonSerializer.Serialize(payload, JsonOptions);
        _emittedSinceHeartbeat++;
        _writer.WriteLine(line);
        return line;
    }

    public string EmitHeartbeat(int intervalSeconds = 900, long droppedEvents = 0)
    {
        var count = System.Threading.Interlocked.Exchange(ref _emittedSinceHeartbeat, 0);
        return Emit(
            eventName: "sys_logging_heartbeat",
            severity: "INFO",
            outcome: "success",
            actor: new SecurityActor("system", "system:audit-heartbeat"),
            source: new SecuritySource("127.0.0.1"),
            message: "Security logging pipeline heartbeat OK",
            category: "system",
            details: new Dictionary<string, object?>
            {
                ["interval_seconds"] = intervalSeconds,
                ["events_emitted_since_last"] = count,
                ["dropped_events"] = droppedEvents
            });
    }

    private static Dictionary<string, object?> RedactDictionary(IReadOnlyDictionary<string, object?> input)
    {
        var output = new Dictionary<string, object?>();
        var count = 0;
        foreach (var (key, value) in input)
        {
            if (count++ >= 25) break;
            if (SensitiveKeyRegex.IsMatch(key))
            {
                output[key] = "[REDACTED]";
            }
            else if (value is string s)
            {
                output[key] = Sanitize(s);
            }
            else
            {
                output[key] = value;
            }
        }
        return output;
    }
}
