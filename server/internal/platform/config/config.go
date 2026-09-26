// SPDX-License-Identifier: Apache-2.0

// Package config parses and validates all Kiln server configuration.
//
// Configuration comes from environment variables prefixed KILN_. Secret values
// may instead be read from a file named by the same variable with a _FILE
// suffix (for Kubernetes secret mounts). This is the only package allowed to
// read the environment (enforced by forbidigo). Invalid configuration fails
// fast at startup with a message that never includes secret values.
//
// Defaults are secure: TLS is required, public sign-up is off, and development
// relaxations apply only when KILN_ENV=development.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Env is the deployment environment.
type Env string

// Supported environments.
const (
	EnvProduction  Env = "production"
	EnvDevelopment Env = "development"
)

// TLSMode says who terminates TLS.
type TLSMode string

// Supported TLS modes.
const (
	// TLSModeServer: kiln-server terminates TLS itself (the default).
	TLSModeServer TLSMode = "server"
	// TLSModeUpstream: a reverse proxy or ingress terminates TLS. The operator
	// asserts that clients only reach Kiln over HTTPS.
	TLSModeUpstream TLSMode = "upstream"
)

// Config is the complete, validated server configuration.
type Config struct {
	Env      Env
	Embedded bool
	HTTP     HTTP
	Log      Log
	DB       DB
	OIDC     OIDC
	Auth     Auth
	Web      Web
	Tracing  Tracing
	Runner   Runner
	Logs     Logs
	NATS     NATS
	GitHub   GitHub
}

// HTTP configures the listener and HTTP behavior.
type HTTP struct {
	Addr              string
	PublicURL         *url.URL
	TLSMode           TLSMode
	TLSCertFile       string
	TLSKeyFile        string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxBodyBytes      int64
	// AllowedOrigins are extra origins (beyond PublicURL's) allowed for CORS,
	// e.g. the desktop app's "tauri://localhost". Never "*".
	AllowedOrigins []string
	// TrustedProxies are peer networks whose X-Forwarded-For is believed when
	// deriving the client IP for rate limits and audit records.
	TrustedProxies []netip.Prefix
	// EgressAllowedPrefixes are private ranges outbound HTTP may reach (e.g. an
	// internal IdP or OTLP collector). Cloud metadata stays blocked regardless.
	EgressAllowedPrefixes []netip.Prefix
}

// Log configures structured logging.
type Log struct {
	Level  slog.Level
	Format string // "json" or "text"
}

// DB configures PostgreSQL.
type DB struct {
	// URL is the full connection string including any password. Secret because
	// it may embed credentials.
	URL      Secret
	MaxConns int32
	// MigrateOnStart applies pending migrations at startup (default true).
	MigrateOnStart bool
}

// OIDC configures the identity provider.
type OIDC struct {
	IssuerURL    string
	ClientID     string
	ClientSecret Secret
	// RequiredAMR, when set, requires the ID token's amr claim to contain at
	// least one of these values (e.g. "mfa").
	RequiredAMR []string
}

// Auth configures sessions and account provisioning.
type Auth struct {
	SessionIdleTimeout     time.Duration
	SessionAbsoluteTimeout time.Duration
	DesktopAccessTokenTTL  time.Duration
	DesktopRefreshTokenTTL time.Duration
	// AutoProvision creates an account on first sign-in for any verified email
	// the IdP authenticates. Off by default (no public sign-up).
	AutoProvision bool
	// AllowedEmailDomains, when set, auto-provisions only matching verified emails.
	AllowedEmailDomains []string
	// BootstrapAdminEmails are provisioned on first sign-in and become instance
	// admins (who may create orgs).
	BootstrapAdminEmails []string
}

// Web configures serving the built web app.
type Web struct {
	// Dir is the directory holding the built SPA. Empty disables serving it.
	Dir string
}

// Runner configures the runner gRPC listener (ADR-0005).
type Runner struct {
	// Addr is the gRPC listen address (default ":9443").
	Addr string
	// CADir holds the runner CA (ca.crt, ca.key). Empty disables the
	// runner listener.
	CADir string
	// Hostnames the runner server certificate is issued for.
	Hostnames []string
}

// Enabled reports whether the runner listener is configured.
func (r Runner) Enabled() bool { return r.CADir != "" }

// Logs configures job log storage (ADR-0007).
type Logs struct {
	// Store is "fs" (a local directory) or "s3".
	Store string
	// Dir is the fs store's directory.
	Dir      string
	MaxBytes int64
	S3       S3
}

// S3 configures an S3-compatible bucket.
type S3 struct {
	Endpoint  string
	Bucket    string
	Region    string
	Prefix    string
	AccessKey string
	SecretKey Secret
	UseTLS    bool
}

// NATS configures the live notification bus. Empty URL uses an in-process
// bus (single replica or --embedded).
type NATS struct {
	URL       string
	CredsFile string
	User      string
	Password  Secret
	// Insecure disables TLS (development only).
	Insecure bool
}

// GitHub configures the GitHub App (ADR-0008). Empty AppID disables it.
type GitHub struct {
	AppID int64
	// PrivateKey is the App's PEM private key (from KILN_GITHUB_APP_PRIVATE_KEY_FILE).
	PrivateKey    Secret
	WebhookSecret Secret
	APIURL        string
}

// Enabled reports whether the GitHub App is configured.
func (g GitHub) Enabled() bool { return g.AppID > 0 }

// Tracing configures OpenTelemetry export.
type Tracing struct {
	// OTLPEndpoint (host:port) enables OTLP/HTTP trace export when set.
	OTLPEndpoint string
	Insecure     bool
}

// Source abstracts the environment and filesystem for testing.
type Source struct {
	LookupEnv func(string) (string, bool)
	ReadFile  func(string) ([]byte, error)
}

// OSSource reads the real process environment and filesystem.
func OSSource() Source {
	return Source{LookupEnv: os.LookupEnv, ReadFile: os.ReadFile}
}

// Load parses and validates configuration. The returned error lists every
// problem found, never including secret values.
func Load(src Source, embedded bool) (*Config, error) {
	p := parser{src: src}
	c := &Config{Embedded: embedded}

	c.Env = Env(p.str("KILN_ENV", string(EnvProduction)))
	isDev := c.Env == EnvDevelopment

	c.HTTP.Addr = p.str("KILN_HTTP_ADDR", ":8080")
	c.HTTP.PublicURL = p.url("KILN_PUBLIC_URL")
	c.HTTP.TLSMode = TLSMode(p.str("KILN_TLS_MODE", string(TLSModeServer)))
	c.HTTP.TLSCertFile = p.str("KILN_TLS_CERT_FILE", "")
	c.HTTP.TLSKeyFile = p.str("KILN_TLS_KEY_FILE", "")
	c.HTTP.ReadHeaderTimeout = p.duration("KILN_HTTP_READ_HEADER_TIMEOUT", 5*time.Second)
	c.HTTP.ReadTimeout = p.duration("KILN_HTTP_READ_TIMEOUT", 30*time.Second)
	c.HTTP.WriteTimeout = p.duration("KILN_HTTP_WRITE_TIMEOUT", 60*time.Second)
	c.HTTP.IdleTimeout = p.duration("KILN_HTTP_IDLE_TIMEOUT", 120*time.Second)
	c.HTTP.ShutdownTimeout = p.duration("KILN_SHUTDOWN_TIMEOUT", 30*time.Second)
	c.HTTP.MaxBodyBytes = p.int64("KILN_HTTP_MAX_BODY_BYTES", 1<<20)
	c.HTTP.AllowedOrigins = p.list("KILN_CORS_ALLOWED_ORIGINS")
	c.HTTP.TrustedProxies = p.prefixes("KILN_TRUSTED_PROXIES")
	c.HTTP.EgressAllowedPrefixes = p.prefixes("KILN_EGRESS_ALLOWED_PREFIXES")

	defaultFormat := "json"
	if isDev {
		defaultFormat = "text"
	}
	c.Log.Level = p.level("KILN_LOG_LEVEL", slog.LevelInfo)
	c.Log.Format = p.str("KILN_LOG_FORMAT", defaultFormat)

	c.DB.URL = p.secret("KILN_DB_URL")
	c.DB.MaxConns = p.int32("KILN_DB_MAX_CONNS", 20)
	c.DB.MigrateOnStart = p.bool("KILN_DB_MIGRATE_ON_START", true)

	c.OIDC.IssuerURL = p.str("KILN_OIDC_ISSUER_URL", "")
	c.OIDC.ClientID = p.str("KILN_OIDC_CLIENT_ID", "")
	c.OIDC.ClientSecret = p.secret("KILN_OIDC_CLIENT_SECRET")
	c.OIDC.RequiredAMR = p.list("KILN_OIDC_REQUIRED_AMR")

	c.Auth.SessionIdleTimeout = p.duration("KILN_SESSION_IDLE_TIMEOUT", time.Hour)
	c.Auth.SessionAbsoluteTimeout = p.duration("KILN_SESSION_ABSOLUTE_TIMEOUT", 12*time.Hour)
	c.Auth.DesktopAccessTokenTTL = p.duration("KILN_DESKTOP_ACCESS_TOKEN_TTL", 15*time.Minute)
	c.Auth.DesktopRefreshTokenTTL = p.duration("KILN_DESKTOP_REFRESH_TOKEN_TTL", 30*24*time.Hour)
	c.Auth.AutoProvision = p.bool("KILN_AUTH_AUTO_PROVISION", false)
	c.Auth.AllowedEmailDomains = lower(p.list("KILN_AUTH_ALLOWED_EMAIL_DOMAINS"))
	c.Auth.BootstrapAdminEmails = lower(p.list("KILN_AUTH_BOOTSTRAP_ADMIN_EMAILS"))

	c.Web.Dir = p.str("KILN_WEB_DIR", "")

	c.Runner.Addr = p.str("KILN_RUNNER_ADDR", ":9443")
	c.Runner.CADir = p.str("KILN_RUNNER_CA_DIR", "")
	c.Runner.Hostnames = lower(p.list("KILN_RUNNER_HOSTNAMES"))

	c.Logs.Store = p.str("KILN_LOG_STORE", "fs")
	defaultLogDir := ""
	if isDev {
		defaultLogDir = "data/logs"
	}
	c.Logs.Dir = p.str("KILN_LOG_DIR", defaultLogDir)
	c.Logs.MaxBytes = p.int64("KILN_LOG_MAX_BYTES", 64<<20)
	c.Logs.S3.Endpoint = p.str("KILN_S3_ENDPOINT", "")
	c.Logs.S3.Bucket = p.str("KILN_S3_BUCKET", "")
	c.Logs.S3.Region = p.str("KILN_S3_REGION", "")
	c.Logs.S3.Prefix = p.str("KILN_S3_PREFIX", "")
	c.Logs.S3.AccessKey = p.str("KILN_S3_ACCESS_KEY_ID", "")
	c.Logs.S3.SecretKey = p.secret("KILN_S3_SECRET_ACCESS_KEY")
	c.Logs.S3.UseTLS = p.bool("KILN_S3_USE_TLS", true)

	c.NATS.URL = p.str("KILN_NATS_URL", "")
	c.NATS.CredsFile = p.str("KILN_NATS_CREDS_FILE", "")
	c.NATS.User = p.str("KILN_NATS_USER", "")
	c.NATS.Password = p.secret("KILN_NATS_PASSWORD")
	c.NATS.Insecure = p.bool("KILN_NATS_INSECURE", false)

	c.GitHub.AppID = p.int64("KILN_GITHUB_APP_ID", 0)
	c.GitHub.PrivateKey = p.secretFile("KILN_GITHUB_APP_PRIVATE_KEY_FILE")
	c.GitHub.WebhookSecret = p.secret("KILN_GITHUB_WEBHOOK_SECRET")
	c.GitHub.APIURL = p.str("KILN_GITHUB_API_URL", "https://api.github.com")

	c.Tracing.OTLPEndpoint = p.str("KILN_OTEL_EXPORTER_OTLP_ENDPOINT", "")
	c.Tracing.Insecure = p.bool("KILN_OTEL_EXPORTER_OTLP_INSECURE", false)

	p.errs = append(p.errs, c.validate()...)
	if len(p.errs) > 0 {
		msgs := make([]string, len(p.errs))
		for i, e := range p.errs {
			msgs[i] = e.Error()
		}
		return nil, errors.New("invalid configuration:\n  - " + strings.Join(msgs, "\n  - "))
	}
	return c, nil
}

// IsDevelopment reports whether development relaxations apply.
func (c *Config) IsDevelopment() bool { return c.Env == EnvDevelopment }

// PublicOrigin returns the scheme://host[:port] origin of the public URL.
func (c *Config) PublicOrigin() string {
	return c.HTTP.PublicURL.Scheme + "://" + c.HTTP.PublicURL.Host
}

func (c *Config) validate() []error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch c.Env {
	case EnvProduction, EnvDevelopment:
	default:
		add("KILN_ENV must be %q or %q", EnvProduction, EnvDevelopment)
	}

	if u := c.HTTP.PublicURL; u != nil {
		switch {
		case u.Scheme == "https":
		case u.Scheme == "http" && c.IsDevelopment() && isLoopbackHost(u.Hostname()):
			// Browsers treat http://localhost as a secure context.
		default:
			add("KILN_PUBLIC_URL must use https (http is allowed only for localhost with KILN_ENV=development)")
		}
		if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			add("KILN_PUBLIC_URL must be an origin only (scheme://host[:port])")
		}
	} else {
		add("KILN_PUBLIC_URL is required")
	}

	switch c.HTTP.TLSMode {
	case TLSModeServer:
		if c.HTTP.TLSCertFile == "" || c.HTTP.TLSKeyFile == "" {
			add("KILN_TLS_CERT_FILE and KILN_TLS_KEY_FILE are required when KILN_TLS_MODE=server")
		}
	case TLSModeUpstream:
	default:
		add("KILN_TLS_MODE must be %q or %q", TLSModeServer, TLSModeUpstream)
	}

	for _, o := range c.HTTP.AllowedOrigins {
		if err := validateOrigin(o); err != nil {
			add("KILN_CORS_ALLOWED_ORIGINS: %v", err)
		}
	}
	if c.HTTP.MaxBodyBytes <= 0 || c.HTTP.MaxBodyBytes > 64<<20 {
		add("KILN_HTTP_MAX_BODY_BYTES must be between 1 and 67108864")
	}
	for name, d := range map[string]time.Duration{
		"KILN_HTTP_READ_HEADER_TIMEOUT": c.HTTP.ReadHeaderTimeout,
		"KILN_HTTP_READ_TIMEOUT":        c.HTTP.ReadTimeout,
		"KILN_HTTP_WRITE_TIMEOUT":       c.HTTP.WriteTimeout,
		"KILN_HTTP_IDLE_TIMEOUT":        c.HTTP.IdleTimeout,
		"KILN_SHUTDOWN_TIMEOUT":         c.HTTP.ShutdownTimeout,
	} {
		if d <= 0 {
			add("%s must be positive", name)
		}
	}

	if c.Log.Format != "json" && c.Log.Format != "text" {
		add("KILN_LOG_FORMAT must be json or text")
	}

	if c.DB.URL.IsZero() {
		add("KILN_DB_URL (or KILN_DB_URL_FILE) is required")
	} else if u, err := url.Parse(c.DB.URL.Reveal()); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		// Do not include err: it can echo the URL, which may contain a password.
		add("KILN_DB_URL must be a postgres:// URL")
	}
	if c.DB.MaxConns < 1 || c.DB.MaxConns > 1000 {
		add("KILN_DB_MAX_CONNS must be between 1 and 1000")
	}

	if c.OIDC.IssuerURL == "" || c.OIDC.ClientID == "" {
		add("KILN_OIDC_ISSUER_URL and KILN_OIDC_CLIENT_ID are required (Kiln has no password login)")
	} else if u, err := url.Parse(c.OIDC.IssuerURL); err != nil || (u.Scheme != "https" && (u.Scheme != "http" || !c.IsDevelopment())) {
		add("KILN_OIDC_ISSUER_URL must be an https URL")
	}

	if c.Auth.SessionIdleTimeout <= 0 || c.Auth.SessionIdleTimeout > c.Auth.SessionAbsoluteTimeout {
		add("KILN_SESSION_IDLE_TIMEOUT must be positive and not exceed KILN_SESSION_ABSOLUTE_TIMEOUT")
	}
	if c.Auth.SessionAbsoluteTimeout > 24*time.Hour {
		add("KILN_SESSION_ABSOLUTE_TIMEOUT must not exceed 24h")
	}
	if c.Auth.DesktopAccessTokenTTL <= 0 || c.Auth.DesktopAccessTokenTTL > time.Hour {
		add("KILN_DESKTOP_ACCESS_TOKEN_TTL must be between 1s and 1h")
	}
	if c.Auth.DesktopRefreshTokenTTL <= 0 || c.Auth.DesktopRefreshTokenTTL > 90*24*time.Hour {
		add("KILN_DESKTOP_REFRESH_TOKEN_TTL must be between 1s and 2160h")
	}

	switch c.Logs.Store {
	case "fs":
		if c.Logs.Dir == "" {
			add("KILN_LOG_DIR is required when KILN_LOG_STORE=fs (a directory outside the database host's backups is recommended)")
		}
	case "s3":
		if c.Logs.S3.Endpoint == "" || c.Logs.S3.Bucket == "" || c.Logs.S3.AccessKey == "" || c.Logs.S3.SecretKey.IsZero() {
			add("KILN_S3_ENDPOINT, KILN_S3_BUCKET, KILN_S3_ACCESS_KEY_ID and KILN_S3_SECRET_ACCESS_KEY are required when KILN_LOG_STORE=s3")
		}
		if strings.Contains(c.Logs.S3.Endpoint, "/") {
			add("KILN_S3_ENDPOINT must be host[:port] without a scheme")
		}
		if !c.Logs.S3.UseTLS && !c.IsDevelopment() {
			add("KILN_S3_USE_TLS=false is allowed only with KILN_ENV=development")
		}
	default:
		add("KILN_LOG_STORE must be fs or s3")
	}
	if c.Logs.MaxBytes < 1<<20 || c.Logs.MaxBytes > 1<<30 {
		add("KILN_LOG_MAX_BYTES must be between 1 MiB and 1 GiB")
	}
	if c.NATS.URL != "" {
		if u, err := url.Parse(c.NATS.URL); err != nil || (u.Scheme != "nats" && u.Scheme != "tls") || u.User != nil {
			add("KILN_NATS_URL must be nats:// or tls:// without credentials (use KILN_NATS_CREDS_FILE or KILN_NATS_USER/PASSWORD)")
		}
		if c.NATS.Insecure && !c.IsDevelopment() {
			add("KILN_NATS_INSECURE is allowed only with KILN_ENV=development")
		}
	}

	if c.GitHub.AppID < 0 {
		add("KILN_GITHUB_APP_ID must be a positive integer")
	}
	if c.GitHub.Enabled() {
		if c.GitHub.PrivateKey.IsZero() {
			add("KILN_GITHUB_APP_PRIVATE_KEY_FILE is required when KILN_GITHUB_APP_ID is set")
		}
		if len(c.GitHub.WebhookSecret.Reveal()) < 20 {
			add("KILN_GITHUB_WEBHOOK_SECRET (or _FILE) of at least 20 characters is required when KILN_GITHUB_APP_ID is set")
		}
		if u, err := url.Parse(c.GitHub.APIURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			add("KILN_GITHUB_API_URL must be an https URL")
		}
	}

	if c.Runner.Enabled() {
		if len(c.Runner.Hostnames) == 0 {
			add("KILN_RUNNER_HOSTNAMES is required when KILN_RUNNER_CA_DIR is set (names runners use to reach this server)")
		}
		for _, h := range c.Runner.Hostnames {
			if net.ParseIP(h) == nil && !hostnamePattern.MatchString(h) {
				add("KILN_RUNNER_HOSTNAMES: %q is not a hostname or IP address", h)
			}
		}
		if _, _, err := net.SplitHostPort(c.Runner.Addr); err != nil {
			add("KILN_RUNNER_ADDR must be host:port")
		}
	}
	return errs
}

var hostnamePattern = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func validateOrigin(o string) error {
	if o == "*" {
		return errors.New(`"*" is not allowed; list explicit origins`)
	}
	u, err := url.Parse(o)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return fmt.Errorf("%q is not an origin (scheme://host[:port])", o)
	}
	return nil
}

func lower(xs []string) []string {
	for i, x := range xs {
		xs[i] = strings.ToLower(x)
	}
	return xs
}

// parser accumulates errors so Load reports every problem at once.
type parser struct {
	src  Source
	errs []error
}

func (p *parser) get(key string) (string, bool) {
	v, ok := p.src.LookupEnv(key)
	return strings.TrimSpace(v), ok && strings.TrimSpace(v) != ""
}

func (p *parser) str(key, def string) string {
	if v, ok := p.get(key); ok {
		return v
	}
	return def
}

func (p *parser) secret(key string) Secret {
	v, hasValue := p.get(key)
	path, hasFile := p.get(key + "_FILE")
	switch {
	case hasValue && hasFile:
		p.errs = append(p.errs, fmt.Errorf("set only one of %s and %s_FILE", key, key))
	case hasFile:
		b, err := p.src.ReadFile(path)
		if err != nil {
			p.errs = append(p.errs, fmt.Errorf("%s_FILE: cannot read file", key))
			return Secret{}
		}
		return NewSecret(strings.TrimRight(string(b), "\r\n"))
	case hasValue:
		return NewSecret(v)
	}
	return Secret{}
}

// secretFile reads a secret that is only accepted from a file (e.g. a
// private key), never from the environment directly.
func (p *parser) secretFile(key string) Secret {
	path, ok := p.get(key)
	if !ok {
		return Secret{}
	}
	b, err := p.src.ReadFile(path)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: cannot read file", key))
		return Secret{}
	}
	return NewSecret(string(b))
}

func (p *parser) url(key string) *url.URL {
	v, ok := p.get(key)
	if !ok {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || u.Host == "" {
		p.errs = append(p.errs, fmt.Errorf("%s must be an absolute URL", key))
		return nil
	}
	return u
}

func (p *parser) duration(key string, def time.Duration) time.Duration {
	v, ok := p.get(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s must be a duration like 30s or 5m", key))
		return def
	}
	return d
}

func (p *parser) int64(key string, def int64) int64 {
	v, ok := p.get(key)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s must be an integer", key))
		return def
	}
	return n
}

func (p *parser) int32(key string, def int32) int32 {
	v, ok := p.get(key)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s must be an integer", key))
		return def
	}
	return int32(n)
}

func (p *parser) bool(key string, def bool) bool {
	v, ok := p.get(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s must be true or false", key))
		return def
	}
	return b
}

func (p *parser) level(key string, def slog.Level) slog.Level {
	v, ok := p.get(key)
	if !ok {
		return def
	}
	var l slog.Level
	if err := l.UnmarshalText([]byte(v)); err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s must be debug, info, warn, or error", key))
		return def
	}
	return l
}

func (p *parser) list(key string) []string {
	v, ok := p.get(key)
	if !ok {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (p *parser) prefixes(key string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range p.list(key) {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			p.errs = append(p.errs, fmt.Errorf("%s: %q is not a CIDR prefix", key, s))
			continue
		}
		out = append(out, pfx.Masked())
	}
	return out
}
