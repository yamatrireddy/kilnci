// SPDX-License-Identifier: Apache-2.0

// Package github is Kiln's GitHub App client (ADR-0008 §1).
//
// It authenticates as the App with short-lived RS256 JWTs and exchanges them
// for installation tokens restricted to a single repository and to the
// minimum permissions each operation needs; tokens are cached in memory
// until five minutes before expiry and are never logged or persisted.
// Repositories are addressed by their immutable numeric ID
// (/repositories/{id}) so renames and transfers cannot redirect a call.
// All HTTP goes through platform/httpclient; responses are size-limited and
// errors never include tokens or response bodies.
package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"go.opentelemetry.io/otel"
)

var tracer = otel.Tracer("github.com/yamatrireddy/kilnci/server/internal/vcs/github")

// ErrNotFound means the repository, file, or ref does not exist or is not
// accessible to the installation.
var ErrNotFound = errors.New("not found on GitHub")

// Options configures the client.
type Options struct {
	AppID      int64
	PrivateKey []byte // PEM (PKCS#1 or PKCS#8 RSA)
	// APIURL defaults to https://api.github.com (set for GitHub Enterprise).
	APIURL string
	// HTTP must be a platform/httpclient client.
	HTTP *http.Client
	Now  func() time.Time
}

// Client talks to GitHub as the Kiln App.
type Client struct {
	appID  int64
	signer jose.Signer
	api    *url.URL
	http   *http.Client
	now    func() time.Time

	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

// New returns a Client.
func New(o Options) (*Client, error) {
	if o.AppID <= 0 || o.HTTP == nil {
		return nil, errors.New("github: app ID and HTTP client are required")
	}
	key, err := parseRSAKey(o.PrivateKey)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, errors.New("github: cannot use the App private key")
	}
	raw := o.APIURL
	if raw == "" {
		raw = "https://api.github.com"
	}
	api, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || api.Scheme != "https" || api.Host == "" || api.User != nil {
		return nil, errors.New("github: API URL must be https://host[/path]")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Client{appID: o.AppID, signer: signer, api: api, http: o.HTTP, now: o.Now, tokens: map[string]cachedToken{}}, nil
}

func parseRSAKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, errors.New("github: App private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, errors.New("github: App private key cannot be parsed")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github: App private key must be RSA")
	}
	return rk, nil
}

// appJWT is valid for 9 minutes (GitHub allows 10), backdated for skew.
func (c *Client) appJWT() (string, error) {
	now := c.now()
	claims := jwt.Claims{
		Issuer:   strconv.FormatInt(c.appID, 10),
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	s, err := jwt.Signed(c.signer).Claims(claims).Serialize()
	if err != nil {
		return "", errors.New("github: sign App JWT")
	}
	return s, nil
}

// Permissions requested for installation tokens.
var (
	PermContentsRead = map[string]string{"contents": "read", "metadata": "read"}
	PermStatusWrite  = map[string]string{"statuses": "write", "metadata": "read"}
	PermMetadataRead = map[string]string{"metadata": "read"}
)

// Token returns an installation token restricted to repoID (0: all of the
// installation's repositories, used only to look a repository up) and perms.
func (c *Client) Token(ctx context.Context, installationID, repoID int64, perms map[string]string) (string, time.Time, error) {
	ctx, span := tracer.Start(ctx, "github.Token")
	defer span.End()
	key := cacheKey(installationID, repoID, perms)
	c.mu.Lock()
	if t, ok := c.tokens[key]; ok && c.now().Before(t.expires.Add(-5*time.Minute)) {
		c.mu.Unlock()
		return t.token, t.expires, nil
	}
	c.mu.Unlock()
	appJWT, err := c.appJWT()
	if err != nil {
		return "", time.Time{}, err
	}
	body := map[string]any{"permissions": perms}
	if repoID > 0 {
		body["repository_ids"] = []int64{repoID}
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	if err := c.do(ctx, http.MethodPost, path, "Bearer "+appJWT, body, http.StatusCreated, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("installation token: %w", err)
	}
	if out.Token == "" || out.ExpiresAt.IsZero() {
		return "", time.Time{}, errors.New("installation token: malformed response")
	}
	c.mu.Lock()
	c.tokens[key] = cachedToken{token: out.Token, expires: out.ExpiresAt}
	c.mu.Unlock()
	return out.Token, out.ExpiresAt, nil
}

func cacheKey(inst, repo int64, perms map[string]string) string {
	keys := make([]string, 0, len(perms))
	for k, v := range perms {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%d/%d/%s", inst, repo, strings.Join(keys, ","))
}

// Installation describes an App installation.
type Installation struct {
	ID           int64
	AccountLogin string
}

// GetInstallation checks that installationID exists for this App.
func (c *Client) GetInstallation(ctx context.Context, installationID int64) (Installation, error) {
	ctx, span := tracer.Start(ctx, "github.GetInstallation")
	defer span.End()
	appJWT, err := c.appJWT()
	if err != nil {
		return Installation{}, err
	}
	var out struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/app/installations/%d", installationID), "Bearer "+appJWT, nil, http.StatusOK, &out); err != nil {
		return Installation{}, fmt.Errorf("get installation: %w", err)
	}
	return Installation{ID: out.ID, AccountLogin: out.Account.Login}, nil
}

// Repository is a repository as seen by an installation.
type Repository struct {
	ID            int64
	FullName      string
	CloneURL      string
	DefaultBranch string
	Private       bool
}

var fullNamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// ValidFullName reports whether s looks like "owner/repo".
func ValidFullName(s string) bool {
	return fullNamePattern.MatchString(s) && !strings.Contains(s, "..")
}

// GetRepository looks a repository up by name through the installation; it
// is ErrNotFound unless the installation can access it.
func (c *Client) GetRepository(ctx context.Context, installationID int64, fullName string) (Repository, error) {
	ctx, span := tracer.Start(ctx, "github.GetRepository")
	defer span.End()
	if !ValidFullName(fullName) {
		return Repository{}, ErrNotFound
	}
	tok, _, err := c.Token(ctx, installationID, 0, PermMetadataRead)
	if err != nil {
		return Repository{}, err
	}
	owner, name, _ := strings.Cut(fullName, "/")
	var out struct {
		ID            int64  `json:"id"`
		FullName      string `json:"full_name"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
	}
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
	if err := c.do(ctx, http.MethodGet, path, "token "+tok, nil, http.StatusOK, &out); err != nil {
		return Repository{}, fmt.Errorf("get repository: %w", err)
	}
	if out.ID <= 0 || !strings.HasPrefix(out.CloneURL, "https://") || out.DefaultBranch == "" {
		return Repository{}, errors.New("get repository: malformed response")
	}
	return Repository{ID: out.ID, FullName: out.FullName, CloneURL: out.CloneURL, DefaultBranch: out.DefaultBranch, Private: out.Private}, nil
}

// GetFile returns a file's content at commit sha, reading at most maxBytes+1
// bytes (callers reject oversized files). ErrNotFound if absent.
func (c *Client) GetFile(ctx context.Context, installationID, repoID int64, filePath, sha string, maxBytes int64) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "github.GetFile")
	defer span.End()
	tok, _, err := c.Token(ctx, installationID, repoID, PermContentsRead)
	if err != nil {
		return nil, err
	}
	u := c.url(fmt.Sprintf("/repositories/%d/contents/%s", repoID, escapePath(filePath)))
	q := u.Query()
	q.Set("ref", sha)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("get file: %w", err)
	}
	c.headers(req, "token "+tok)
	req.Header.Set("Accept", "application/vnd.github.raw")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get file: %w", redactURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get file: GitHub answered %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("get file: %w", err)
	}
	return b, nil
}

// ResolveBranch returns the commit SHA a branch points at.
func (c *Client) ResolveBranch(ctx context.Context, installationID, repoID int64, branch string) (string, error) {
	ctx, span := tracer.Start(ctx, "github.ResolveBranch")
	defer span.End()
	tok, _, err := c.Token(ctx, installationID, repoID, PermContentsRead)
	if err != nil {
		return "", err
	}
	var out struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	path := fmt.Sprintf("/repositories/%d/git/ref/heads/%s", repoID, escapePath(branch))
	if err := c.do(ctx, http.MethodGet, path, "token "+tok, nil, http.StatusOK, &out); err != nil {
		return "", fmt.Errorf("resolve branch: %w", err)
	}
	if out.Object.Type != "commit" {
		return "", ErrNotFound
	}
	return out.Object.SHA, nil
}

// Status is a commit status to post.
type Status struct {
	State       string // pending, success, failure, error
	Context     string
	Description string
	TargetURL   string
}

// CreateStatus posts a commit status (T-43: only the control plane holds
// the App key).
func (c *Client) CreateStatus(ctx context.Context, installationID, repoID int64, sha string, s Status) error {
	ctx, span := tracer.Start(ctx, "github.CreateStatus")
	defer span.End()
	tok, _, err := c.Token(ctx, installationID, repoID, PermStatusWrite)
	if err != nil {
		return err
	}
	body := map[string]string{"state": s.State, "context": s.Context, "description": s.Description, "target_url": s.TargetURL}
	if err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repositories/%d/statuses/%s", repoID, url.PathEscape(sha)), "token "+tok, body, http.StatusCreated, nil); err != nil {
		return fmt.Errorf("create status: %w", err)
	}
	return nil
}

// url joins the API base with path, whose segments are already escaped.
func (c *Client) url(path string) *url.URL {
	u, err := url.Parse(strings.TrimRight(c.api.String(), "/") + path)
	if err != nil {
		return &url.URL{Scheme: "https", Host: "invalid.invalid"}
	}
	return u
}

func (c *Client) headers(req *http.Request, auth string) {
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

const maxJSONResponse = 1 << 20

// do sends a JSON request and decodes a JSON response. Error messages carry
// only the status code: bodies and URLs can echo tokens or private data.
func (c *Client) do(ctx context.Context, method, path, auth string, in any, want int, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path).String(), body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	c.headers(req, auth)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return redactURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	lr := io.LimitReader(resp.Body, maxJSONResponse)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		_, _ = io.Copy(io.Discard, lr)
		return ErrNotFound
	case resp.StatusCode != want:
		_, _ = io.Copy(io.Discard, lr)
		return fmt.Errorf("GitHub answered %d", resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, lr)
		return nil
	}
	if err := json.NewDecoder(lr).Decode(out); err != nil {
		return errors.New("malformed GitHub response")
	}
	return nil
}

// redactURL drops the request URL from transport errors.
func redactURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s request failed: %w", ue.Op, ue.Err)
	}
	return err
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}
