// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Test-only fake values; not real credentials.
const (
	fakeDBURL      = "postgres://kiln:fake-db-password@db:5432/kiln"
	fakeOIDCSecret = "fake-oidc-client-secret"
)

func source(env map[string]string, files map[string]string) Source {
	return Source{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		ReadFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, errors.New("no such file")
		},
	}
}

func validEnv() map[string]string {
	return map[string]string{
		"KILN_PUBLIC_URL":         "https://kiln.example.com",
		"KILN_TLS_MODE":           "upstream",
		"KILN_DB_URL":             fakeDBURL,
		"KILN_OIDC_ISSUER_URL":    "https://idp.example.com",
		"KILN_OIDC_CLIENT_ID":     "kiln",
		"KILN_OIDC_CLIENT_SECRET": fakeOIDCSecret,
		"KILN_LOG_DIR":            "/var/lib/kiln/logs",
	}
}

func TestLoad_ValidMinimal_UsesSecureDefaults(t *testing.T) {
	c, err := Load(source(validEnv(), nil), false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Env != EnvProduction {
		t.Errorf("Env = %q, want production", c.Env)
	}
	if c.Auth.AutoProvision {
		t.Error("public sign-up must default off")
	}
	if c.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want json in production", c.Log.Format)
	}
	if c.HTTP.MaxBodyBytes != 1<<20 {
		t.Errorf("MaxBodyBytes = %d, want 1 MiB", c.HTTP.MaxBodyBytes)
	}
	if c.Auth.SessionIdleTimeout != time.Hour || c.Auth.SessionAbsoluteTimeout != 12*time.Hour {
		t.Errorf("session timeouts = %v/%v, want 1h/12h", c.Auth.SessionIdleTimeout, c.Auth.SessionAbsoluteTimeout)
	}
	if c.PublicOrigin() != "https://kiln.example.com" {
		t.Errorf("PublicOrigin = %q", c.PublicOrigin())
	}
	if !c.DB.MigrateOnStart {
		t.Error("MigrateOnStart should default true")
	}
}

func TestLoad_RunnerListener(t *testing.T) {
	c, err := Load(source(validEnv(), nil), false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Runner.Enabled() || c.Runner.Addr != ":9443" {
		t.Fatalf("runner listener must be off by default: %+v", c.Runner)
	}
	env := validEnv()
	env["KILN_RUNNER_CA_DIR"] = "/etc/kiln/runner-ca"
	env["KILN_RUNNER_HOSTNAMES"] = "Runners.Example.com, 10.0.0.5"
	c, err = Load(source(env, nil), false)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Runner.Enabled() || c.Runner.Hostnames[0] != "runners.example.com" || c.Runner.Hostnames[1] != "10.0.0.5" {
		t.Fatalf("runner = %+v", c.Runner)
	}
}

func TestLoad_TLSServerModeIsDefault_RequiresCert(t *testing.T) {
	env := validEnv()
	delete(env, "KILN_TLS_MODE")
	_, err := Load(source(env, nil), false)
	if err == nil || !strings.Contains(err.Error(), "KILN_TLS_CERT_FILE") {
		t.Fatalf("want TLS cert error, got %v", err)
	}
}

func TestLoad_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantMsg string
	}{
		{"missing public url", func(e map[string]string) { delete(e, "KILN_PUBLIC_URL") }, "KILN_PUBLIC_URL is required"},
		{"http public url in prod", func(e map[string]string) { e["KILN_PUBLIC_URL"] = "http://kiln.example.com" }, "must use https"},
		{"http non-loopback in dev", func(e map[string]string) {
			e["KILN_ENV"] = "development"
			e["KILN_PUBLIC_URL"] = "http://kiln.example.com"
		}, "must use https"},
		{"public url with path", func(e map[string]string) { e["KILN_PUBLIC_URL"] = "https://kiln.example.com/app" }, "origin only"},
		{"public url with userinfo", func(e map[string]string) { e["KILN_PUBLIC_URL"] = "https://u:p@kiln.example.com" }, "origin only"},
		{"unknown env", func(e map[string]string) { e["KILN_ENV"] = "staging" }, "KILN_ENV"},
		{"wildcard cors", func(e map[string]string) { e["KILN_CORS_ALLOWED_ORIGINS"] = "*" }, "not allowed"},
		{"cors not origin", func(e map[string]string) { e["KILN_CORS_ALLOWED_ORIGINS"] = "https://a.example/x" }, "not an origin"},
		{"missing db", func(e map[string]string) { delete(e, "KILN_DB_URL") }, "KILN_DB_URL"},
		{"non-postgres db", func(e map[string]string) { e["KILN_DB_URL"] = "mysql://x" }, "postgres://"},
		{"missing oidc", func(e map[string]string) { delete(e, "KILN_OIDC_ISSUER_URL") }, "no password login"},
		{"http issuer in prod", func(e map[string]string) { e["KILN_OIDC_ISSUER_URL"] = "http://idp.example.com" }, "https URL"},
		{"bad duration", func(e map[string]string) { e["KILN_SESSION_IDLE_TIMEOUT"] = "forever" }, "duration"},
		{"idle exceeds absolute", func(e map[string]string) { e["KILN_SESSION_IDLE_TIMEOUT"] = "13h" }, "not exceed"},
		{"absolute too long", func(e map[string]string) {
			e["KILN_SESSION_ABSOLUTE_TIMEOUT"] = "48h"
		}, "24h"},
		{"body limit zero", func(e map[string]string) { e["KILN_HTTP_MAX_BODY_BYTES"] = "0" }, "MAX_BODY_BYTES"},
		{"bad bool", func(e map[string]string) { e["KILN_AUTH_AUTO_PROVISION"] = "yes please" }, "true or false"},
		{"bad level", func(e map[string]string) { e["KILN_LOG_LEVEL"] = "loud" }, "KILN_LOG_LEVEL"},
		{"bad format", func(e map[string]string) { e["KILN_LOG_FORMAT"] = "xml" }, "KILN_LOG_FORMAT"},
		{"bad proxy cidr", func(e map[string]string) { e["KILN_TRUSTED_PROXIES"] = "10.0.0.0/33" }, "CIDR"},
		{"secret and file both set", func(e map[string]string) { e["KILN_OIDC_CLIENT_SECRET_FILE"] = "/run/x" }, "only one of"},
		{"unreadable secret file", func(e map[string]string) {
			delete(e, "KILN_OIDC_CLIENT_SECRET")
			e["KILN_OIDC_CLIENT_SECRET_FILE"] = "/missing"
		}, "cannot read"},
		{"bad tls mode", func(e map[string]string) { e["KILN_TLS_MODE"] = "none" }, "KILN_TLS_MODE"},
		{"access ttl too long", func(e map[string]string) { e["KILN_DESKTOP_ACCESS_TOKEN_TTL"] = "2h" }, "ACCESS_TOKEN_TTL"},
		{"refresh ttl too long", func(e map[string]string) { e["KILN_DESKTOP_REFRESH_TOKEN_TTL"] = "3000h" }, "REFRESH_TOKEN_TTL"},
		{"max conns", func(e map[string]string) { e["KILN_DB_MAX_CONNS"] = "0" }, "MAX_CONNS"},
		{"bad int", func(e map[string]string) { e["KILN_DB_MAX_CONNS"] = "many" }, "integer"},
		{"negative timeout", func(e map[string]string) { e["KILN_SHUTDOWN_TIMEOUT"] = "-1s" }, "positive"},
		{"unknown log store", func(e map[string]string) { e["KILN_LOG_STORE"] = "gcs" }, "KILN_LOG_STORE"},
		{"fs store without dir", func(e map[string]string) { delete(e, "KILN_LOG_DIR") }, "KILN_LOG_DIR is required"},
		{"s3 without credentials", func(e map[string]string) {
			e["KILN_LOG_STORE"] = "s3"
			e["KILN_S3_ENDPOINT"] = "minio:9000"
		}, "KILN_S3_BUCKET"},
		{"s3 endpoint with scheme", func(e map[string]string) {
			e["KILN_LOG_STORE"] = "s3"
			e["KILN_S3_ENDPOINT"] = "https://minio:9000"
		}, "without a scheme"},
		{"s3 plaintext in prod", func(e map[string]string) {
			e["KILN_LOG_STORE"] = "s3"
			e["KILN_S3_ENDPOINT"] = "minio:9000"
			e["KILN_S3_USE_TLS"] = "false"
		}, "KILN_S3_USE_TLS"},
		{"nats url with password", func(e map[string]string) { e["KILN_NATS_URL"] = "nats://u:p@nats:4222" }, "without credentials"},
		{"insecure nats in prod", func(e map[string]string) {
			e["KILN_NATS_URL"] = "nats://nats:4222"
			e["KILN_NATS_INSECURE"] = "true"
		}, "KILN_NATS_INSECURE"},
		{"tiny log limit", func(e map[string]string) { e["KILN_LOG_MAX_BYTES"] = "10" }, "KILN_LOG_MAX_BYTES"},
		{"runner ca without hostnames", func(e map[string]string) { e["KILN_RUNNER_CA_DIR"] = "/ca" }, "KILN_RUNNER_HOSTNAMES is required"},
		{"bad runner hostname", func(e map[string]string) {
			e["KILN_RUNNER_CA_DIR"] = "/ca"
			e["KILN_RUNNER_HOSTNAMES"] = "runners.example.com,bad_host!"
		}, "not a hostname"},
		{"bad runner addr", func(e map[string]string) {
			e["KILN_RUNNER_CA_DIR"] = "/ca"
			e["KILN_RUNNER_HOSTNAMES"] = "runners.example.com"
			e["KILN_RUNNER_ADDR"] = "9443"
		}, "KILN_RUNNER_ADDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			tt.mutate(env)
			_, err := Load(source(env, nil), false)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q does not mention %q", err, tt.wantMsg)
			}
		})
	}
}

func TestLoad_ReportsAllErrorsAtOnce(t *testing.T) {
	_, err := Load(source(map[string]string{"KILN_TLS_MODE": "upstream"}, nil), false)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"KILN_PUBLIC_URL", "KILN_DB_URL", "KILN_OIDC_ISSUER_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %s: %v", want, err)
		}
	}
}

func TestLoad_ErrorsNeverContainSecrets(t *testing.T) {
	env := validEnv()
	env["KILN_DB_URL"] = "mysql://kiln:" + fakeOIDCSecret + "@db/kiln" // wrong scheme, embeds a secret
	env["KILN_PUBLIC_URL"] = "http://nope"
	_, err := Load(source(env, nil), false)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), fakeOIDCSecret) {
		t.Fatalf("error leaks secret: %v", err)
	}
}

func TestLoad_SecretFromFile(t *testing.T) {
	env := validEnv()
	delete(env, "KILN_OIDC_CLIENT_SECRET")
	env["KILN_OIDC_CLIENT_SECRET_FILE"] = "/run/secrets/oidc"
	c, err := Load(source(env, map[string]string{"/run/secrets/oidc": fakeOIDCSecret + "\n"}), false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.OIDC.ClientSecret.Reveal() != fakeOIDCSecret {
		t.Fatalf("secret from file not trimmed/loaded correctly")
	}
}

func TestLoad_DevelopmentAllowsLocalhostHTTP(t *testing.T) {
	env := validEnv()
	env["KILN_ENV"] = "development"
	env["KILN_PUBLIC_URL"] = "http://localhost:8080"
	env["KILN_OIDC_ISSUER_URL"] = "http://localhost:5556/dex"
	env["KILN_CORS_ALLOWED_ORIGINS"] = "tauri://localhost, http://tauri.localhost"
	env["KILN_TRUSTED_PROXIES"] = "10.1.2.3/8"
	env["KILN_EGRESS_ALLOWED_PREFIXES"] = "127.0.0.1/32"
	env["KILN_AUTH_BOOTSTRAP_ADMIN_EMAILS"] = "Admin@Example.com"
	c, err := Load(source(env, nil), true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Log.Format != "text" || !c.Embedded || !c.IsDevelopment() {
		t.Errorf("dev defaults not applied: %+v", c.Log)
	}
	if len(c.HTTP.AllowedOrigins) != 2 {
		t.Errorf("AllowedOrigins = %v", c.HTTP.AllowedOrigins)
	}
	if c.HTTP.TrustedProxies[0].String() != "10.0.0.0/8" {
		t.Errorf("proxy prefix not masked: %v", c.HTTP.TrustedProxies)
	}
	if len(c.HTTP.EgressAllowedPrefixes) != 1 {
		t.Errorf("EgressAllowedPrefixes = %v", c.HTTP.EgressAllowedPrefixes)
	}
	if c.Auth.BootstrapAdminEmails[0] != "admin@example.com" {
		t.Errorf("emails not lowercased: %v", c.Auth.BootstrapAdminEmails)
	}
}

func TestSecret_NeverFormatsValue(t *testing.T) {
	s := NewSecret(fakeOIDCSecret)
	type wrapper struct{ S Secret }
	outputs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v %s %q %#v %+v", s, s, s, s, s),
		fmt.Sprintf("%+v %#v", wrapper{s}, wrapper{s}),
		s.LogValue().String(),
	}
	b, _ := json.Marshal(wrapper{s})
	outputs = append(outputs, string(b))
	txt, _ := s.MarshalText()
	outputs = append(outputs, string(txt))
	var buf strings.Builder
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "secret", s)
	outputs = append(outputs, buf.String())
	for _, o := range outputs {
		if strings.Contains(o, fakeOIDCSecret) {
			t.Fatalf("secret leaked in %q", o)
		}
	}
	if s.Reveal() != fakeOIDCSecret || s.IsZero() || !(Secret{}).IsZero() {
		t.Fatal("Reveal/IsZero wrong")
	}
}
