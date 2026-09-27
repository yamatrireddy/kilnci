// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// maxVaultResponse bounds how much of a Vault response is read.
const maxVaultResponse = 64 << 10

// vaultCiphertext is Transit's ciphertext format; the key version is
// recorded as part of the key ID.
var vaultCiphertext = regexp.MustCompile(`^vault:v([0-9]{1,9}):[A-Za-z0-9+/=]+$`)

// maxVaultCiphertext bounds a Transit ciphertext for a 32-byte DEK.
const maxVaultCiphertext = 4096

// VaultOptions configures a VaultWrapper.
type VaultOptions struct {
	// Client must come from platform/httpclient (timeouts, SSRF policy).
	Client *http.Client
	// Addr is Vault's base URL, e.g. https://vault.internal:8200.
	Addr *url.URL
	// Mount and Key name the Transit engine mount and a derived key. Both
	// are validated by platform/config to contain no path characters.
	Mount, Key string
	// TokenFile holds the Vault token; it is read on every call so a Vault
	// agent can renew it in place.
	TokenFile string
	// Namespace is the Vault Enterprise namespace, or empty.
	Namespace string
}

// VaultWrapper wraps DEKs with HashiCorp Vault Transit (ADR-0009 §2,
// provider "vault"). The org ID is sent as the derivation context, so the
// Transit key must be created with derived=true.
type VaultWrapper struct {
	opts VaultOptions
}

// Vault path segments and namespaces; kept in sync with platform/config,
// and checked again here so no caller can build a path outside Transit.
var (
	vaultSegment   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	vaultNamespace = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}(/[A-Za-z0-9_-]{1,64}){0,7}$`)
)

// maxVaultToken bounds how much of the token file is read.
const maxVaultToken = 8 << 10

// NewVaultWrapper returns a Transit-backed KeyWrapper. The client is copied
// and never follows redirects: a redirect would resend the token (and, on
// 307/308, a plaintext DEK) to whatever host it names. Call Check at startup.
func NewVaultWrapper(opts VaultOptions) (*VaultWrapper, error) {
	if opts.Client == nil || opts.Addr == nil || opts.TokenFile == "" {
		return nil, errors.New("vault: client, address, and token file are required")
	}
	if !vaultSegment.MatchString(opts.Mount) || !vaultSegment.MatchString(opts.Key) ||
		(opts.Namespace != "" && !vaultNamespace.MatchString(opts.Namespace)) {
		return nil, errors.New("vault: mount, key, or namespace contains characters that are not allowed")
	}
	a := opts.Addr
	if (a.Scheme != "https" && a.Scheme != "http") || a.Host == "" || a.User != nil || (a.Path != "" && a.Path != "/") || a.RawQuery != "" {
		return nil, errors.New("vault: address must be a base URL without credentials, path, or query")
	}
	c := *opts.Client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	opts.Client = &c
	return &VaultWrapper{opts: opts}, nil
}

// ErrUnsafeVaultKey is returned by Check when the Transit key's settings
// would weaken the design (ADR-0009 §2).
var ErrUnsafeVaultKey = errors.New("vault transit key is not configured safely")

// VaultKeyInfo is what Check learned about the Transit key.
type VaultKeyInfo struct {
	LatestVersion        int
	MinDecryptionVersion int
	// DeletionAllowed is not fatal but worth a startup warning.
	DeletionAllowed bool
}

// Check reads the Transit key's settings and fails closed unless the key is
// derived (so the org context binds each DEK), not exportable, and has no
// plaintext backup. It also proves the token file is readable.
func (v *VaultWrapper) Check(ctx context.Context) (VaultKeyInfo, error) {
	var out struct {
		Data struct {
			Derived              bool `json:"derived"`
			Exportable           bool `json:"exportable"`
			AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
			DeletionAllowed      bool `json:"deletion_allowed"`
			LatestVersion        int  `json:"latest_version"`
			MinDecryptionVersion int  `json:"min_decryption_version"`
		} `json:"data"`
	}
	if err := v.do(ctx, http.MethodGet, v.opts.Addr.JoinPath("v1", v.opts.Mount, "keys", v.opts.Key), nil, &out); err != nil {
		return VaultKeyInfo{}, err
	}
	d := out.Data
	switch {
	case !d.Derived:
		return VaultKeyInfo{}, fmt.Errorf("%w: key must be created with derived=true", ErrUnsafeVaultKey)
	case d.Exportable:
		return VaultKeyInfo{}, fmt.Errorf("%w: key must not be exportable", ErrUnsafeVaultKey)
	case d.AllowPlaintextBackup:
		return VaultKeyInfo{}, fmt.Errorf("%w: key must not allow plaintext backup", ErrUnsafeVaultKey)
	case d.LatestVersion < 1:
		return VaultKeyInfo{}, fmt.Errorf("%w: key has no versions", ErrUnsafeVaultKey)
	}
	return VaultKeyInfo{LatestVersion: d.LatestVersion, MinDecryptionVersion: d.MinDecryptionVersion, DeletionAllowed: d.DeletionAllowed}, nil
}

type transitRequest struct {
	Plaintext  string `json:"plaintext,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Context    string `json:"context"`
}

type transitResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
	} `json:"data"`
}

// Wrap implements KeyWrapper.
func (v *VaultWrapper) Wrap(ctx context.Context, orgID string, dek []byte) (WrappedKey, error) {
	if orgID == "" {
		return WrappedKey{}, errors.New("vault: org ID is required")
	}
	if len(dek) != KeySize {
		return WrappedKey{}, fmt.Errorf("data key must be %d bytes", KeySize)
	}
	res, err := v.call(ctx, "encrypt", transitRequest{Plaintext: base64.StdEncoding.EncodeToString(dek), Context: vaultContext(orgID)})
	if err != nil {
		return WrappedKey{}, err
	}
	return v.wrapped(res.Data.Ciphertext)
}

// Unwrap implements KeyWrapper.
func (v *VaultWrapper) Unwrap(ctx context.Context, orgID string, wk WrappedKey) ([]byte, error) {
	if orgID == "" {
		return nil, errors.New("vault: org ID is required")
	}
	ct, err := v.ciphertext(wk)
	if err != nil {
		return nil, err
	}
	res, err := v.call(ctx, "decrypt", transitRequest{Ciphertext: ct, Context: vaultContext(orgID)})
	if err != nil {
		return nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(res.Data.Plaintext)
	if err != nil || len(dek) != KeySize {
		clear(dek)
		return nil, fmt.Errorf("vault decrypt: %w", ErrDecrypt)
	}
	return dek, nil
}

// Rewrap implements KeyWrapper using Transit's rewrap, so the DEK never
// leaves Vault in plaintext during rotation.
func (v *VaultWrapper) Rewrap(ctx context.Context, orgID string, wk WrappedKey) (WrappedKey, error) {
	if orgID == "" {
		return WrappedKey{}, errors.New("vault: org ID is required")
	}
	ct, err := v.ciphertext(wk)
	if err != nil {
		return WrappedKey{}, err
	}
	res, err := v.call(ctx, "rewrap", transitRequest{Ciphertext: ct, Context: vaultContext(orgID)})
	if err != nil {
		return WrappedKey{}, err
	}
	return v.wrapped(res.Data.Ciphertext)
}

func vaultContext(orgID string) string {
	return base64.StdEncoding.EncodeToString([]byte("kiln-org:" + orgID))
}

func (v *VaultWrapper) keyPrefix() string { return "vault:" + v.opts.Key + ":" }

func (v *VaultWrapper) wrapped(ct string) (WrappedKey, error) {
	var m []string
	if len(ct) <= maxVaultCiphertext {
		m = vaultCiphertext.FindStringSubmatch(ct)
	}
	if m == nil {
		return WrappedKey{}, errors.New("vault: unexpected ciphertext format")
	}
	return WrappedKey{KeyID: v.keyPrefix() + "v" + m[1], Ciphertext: []byte(ct)}, nil
}

func (v *VaultWrapper) ciphertext(wk WrappedKey) (string, error) {
	ct := string(wk.Ciphertext)
	var m []string
	if len(ct) <= maxVaultCiphertext {
		m = vaultCiphertext.FindStringSubmatch(ct)
	}
	if m == nil || wk.KeyID != v.keyPrefix()+"v"+m[1] {
		return "", ErrUnknownKey
	}
	return ct, nil
}

func (v *VaultWrapper) token() (string, error) {
	f, err := os.Open(v.opts.TokenFile)
	if err != nil {
		return "", errors.New("vault: cannot read token file")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxVaultToken+1))
	if err != nil || len(b) > maxVaultToken {
		return "", errors.New("vault: cannot read token file")
	}
	t := strings.TrimSpace(string(b))
	if t == "" || strings.ContainsAny(t, "\r\n\x00") {
		return "", errors.New("vault: token file is empty or malformed")
	}
	return t, nil
}

// call POSTs a Transit operation to /v1/<mount>/<op>/<key>.
func (v *VaultWrapper) call(ctx context.Context, op string, body transitRequest) (*transitResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vault %s: %w", op, err)
	}
	var out transitResponse
	if err := v.do(ctx, http.MethodPost, v.opts.Addr.JoinPath("v1", v.opts.Mount, op, v.opts.Key), payload, &out); err != nil {
		if errors.Is(err, errVaultBadRequest) && op != "encrypt" {
			// Transit answers 400 when a ciphertext does not open under
			// this context (another org's DEK, or tampering).
			return nil, fmt.Errorf("vault %s: %w", op, ErrDecrypt)
		}
		return nil, fmt.Errorf("vault %s: %w", op, err)
	}
	return &out, nil
}

var errVaultBadRequest = errors.New("vault rejected the request (400)")

// do sends one request. Errors carry the HTTP status but never the request
// or response body.
func (v *VaultWrapper) do(ctx context.Context, method string, u *url.URL, payload []byte, out any) error {
	tok, err := v.token()
	if err != nil {
		return err
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("vault request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Vault-Token", tok)
	req.Header.Set("X-Vault-Request", "true")
	if v.opts.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.opts.Namespace)
	}
	resp, err := v.opts.Client.Do(req)
	if err != nil {
		return fmt.Errorf("vault request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusBadRequest:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxVaultResponse))
		return errVaultBadRequest
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxVaultResponse))
		return fmt.Errorf("vault redirected (status %d); set KILN_VAULT_ADDR to the active node or a forwarding load balancer", resp.StatusCode)
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxVaultResponse))
		return fmt.Errorf("vault: unexpected status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxVaultResponse)).Decode(out); err != nil {
		return errors.New("vault: malformed response")
	}
	return nil
}
