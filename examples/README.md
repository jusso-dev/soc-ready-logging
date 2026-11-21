# Drop-In Reference Security Loggers

These minimal, zero-external-dependency wrappers implement the canonical [`schemas/security-event.schema.json`](../schemas/security-event.schema.json) contract out of the box:

- **Two-stream marker**: Always sets `stream: "security"` (NDJSON, one line per event)
- **UTC ISO-8601 timestamps**: Always UTC with trailing `Z` (ACSC ISM-0988)
- **Automatic redaction**: Denylist key scrubbing + regex scrubbing for Bearer tokens, JWTs, PEM blocks, and sensitive patterns
- **CWE-117 log injection safety**: Strips ASCII control characters (`\r`, `\n`, `\t`, NUL) and ANSI escape codes from all string values
- **Safe session correlation**: Helper to emit `sha256:<prefix>` hashes instead of raw session cookies/tokens

| Language | File | Requirements |
|---|---|---|
| TypeScript / Node.js | [`typescript/security-logger.ts`](./typescript/security-logger.ts) | Node 18+ (built-in `node:crypto`, `node:os`) |
| Python | [`python/security_logger.py`](./python/security_logger.py) | Python 3.9+ standard library only |
| C# / .NET | [`csharp/SecurityAuditLogger.cs`](./csharp/SecurityAuditLogger.cs) | .NET 8/9/10 (`System.Text.Json`) |
| Go | [`go/security_logger.go`](./go/security_logger.go) | Go 1.21+ standard library only |

Copy the file that matches your stack into your application's `src/security/` folder (or let the `soc-logging-implement` agent skill adapt it directly to your framework).
