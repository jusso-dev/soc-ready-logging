// Package seclog provides a minimal, stdlib-only SOC-ready SecurityLogger (Go 1.21+).
// Aligns with OWASP Logging Vocabulary / ASVS V16 and ACSC ISM System Monitoring.
package seclog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var (
	sensitiveKeyRe = regexp.MustCompile(`(?i)(pass(word|wd|phrase)?|secret|token|authorization|cookie|api[_-]?key|private[_-]?key|tfn|medicare|ssn|credit[_-]?card|cvv|pin|otp)`)
	bearerRe       = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`)
	jwtRe          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	ansiRe         = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	controlRe      = regexp.MustCompile(`[\x00-\x1f\x7f]+`)
)

type AppMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Component   string `json:"component,omitempty"`
	Environment string `json:"environment"`
	Version     string `json:"version"`
	Host        string `json:"host,omitempty"`
}

type Actor struct {
	Type           string   `json:"type"`
	ID             string   `json:"id"`
	Username       string   `json:"username,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	TenantID       string   `json:"tenant_id,omitempty"`
	SessionIDHash  string   `json:"session_id_hash,omitempty"`
	ImpersonatedBy string   `json:"impersonated_by,omitempty"`
}

type Source struct {
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent,omitempty"`
	GeoCountry string `json:"geo_country,omitempty"`
}

type Target struct {
	Type           string `json:"type,omitempty"`
	ID             string `json:"id,omitempty"`
	Name           string `json:"name,omitempty"`
	Classification string `json:"classification,omitempty"`
}

type EventInput struct {
	Event         string
	Category      string
	Severity      string
	Outcome       string
	Actor         Actor
	Source        Source
	Target        *Target
	CorrelationID string
	Reason        string
	Message       string
	Details       map[string]any
}

type SecurityLogger struct {
	app     AppMetadata
	out     io.Writer
	counter atomic.Int64
}

func New(app AppMetadata, out io.Writer) *SecurityLogger {
	if app.Host == "" {
		if h, err := os.Hostname(); err == nil {
			app.Host = h
		}
	}
	if out == nil {
		out = os.Stdout
	}
	return &SecurityLogger{app: app, out: out}
}

func Sanitize(s string, maxLen int) string {
	clean := ansiRe.ReplaceAllString(s, "")
	clean = controlRe.ReplaceAllString(clean, " ")
	clean = bearerRe.ReplaceAllString(clean, "[REDACTED]")
	clean = jwtRe.ReplaceAllString(clean, "[REDACTED]")
	clean = strings.TrimSpace(clean)
	if len(clean) > maxLen {
		return clean[:maxLen]
	}
	return clean
}

func HashSessionID(raw, salt string) string {
	sum := sha256.Sum256([]byte(salt + ":" + raw))
	return "sha256:" + hex.EncodeToString(sum[:])[:32]
}

func redactDetails(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	i := 0
	for k, v := range in {
		if i >= 25 {
			break
		}
		i++
		if sensitiveKeyRe.MatchString(k) {
			out[k] = "[REDACTED]"
			continue
		}
		if s, ok := v.(string); ok {
			out[k] = Sanitize(s, 512)
		} else {
			out[k] = v
		}
	}
	return out
}

func (l *SecurityLogger) Emit(in EventInput) (string, error) {
	in.Actor.ID = Sanitize(in.Actor.ID, 128)
	in.Actor.Username = Sanitize(in.Actor.Username, 128)
	in.Source.IP = Sanitize(in.Source.IP, 45)
	in.Source.UserAgent = Sanitize(in.Source.UserAgent, 512)

	record := map[string]any{
		"schema_version": "1.0.0",
		"timestamp":      time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"stream":         "security",
		"event":          Sanitize(in.Event, 80),
		"severity":       in.Severity,
		"outcome":        in.Outcome,
		"app":            l.app,
		"actor":          in.Actor,
		"source":         in.Source,
		"correlation_id": Sanitize(in.CorrelationID, 128),
		"message":        Sanitize(in.Message, 512),
	}
	if in.Category != "" {
		record["category"] = in.Category
	}
	if in.Target != nil {
		record["target"] = in.Target
	}
	if in.Reason != "" {
		record["reason"] = Sanitize(in.Reason, 128)
	}
	if len(in.Details) > 0 {
		record["details"] = redactDetails(in.Details)
	}

	b, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	line := string(b)
	l.counter.Add(1)
	_, err = fmt.Fprintln(l.out, line)
	return line, err
}
