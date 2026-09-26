// SPDX-License-Identifier: Apache-2.0

// Package identity manages a runner's credentials on disk (ADR-0005):
// its private key (never leaves the host, mode 0600), its short-lived client
// certificate, and the pinned Kiln runner CA. Registration and renewal
// always trust only that CA, so a public-CA mis-issuance cannot intercept
// the runner. Renewal writes the new key before asking for a certificate,
// so a crash mid-renewal is retried with the same key (which the server
// treats as an idempotent retry, not as credential reuse).
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
)

// Files in the state directory.
const (
	keyFile        = "key.pem"
	pendingKeyFile = "key.pending.pem"
	certFile       = "cert.pem"
	caFile         = "ca.pem"
	metaFile       = "runner.json"
)

// ProtocolVersion is the runner protocol this runner speaks.
const ProtocolVersion uint32 = 1

type meta struct {
	RunnerID string `json:"runnerId"`
	Server   string `json:"server"`
}

// Identity is a registered runner's credentials.
type Identity struct {
	root     *os.Root
	runnerID string
	server   string
	caPool   *x509.CertPool

	mu   sync.Mutex
	cert tls.Certificate
	leaf *x509.Certificate
}

// RunnerID returns the server-assigned runner ID.
func (id *Identity) RunnerID() string { return id.runnerID }

// Server returns the server address (host:port).
func (id *Identity) Server() string { return id.server }

func openState(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	return root, nil
}

func writeFile(root *os.Root, name string, data []byte, mode os.FileMode) error {
	tmp := name + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func readFile(root *os.Root, name string) ([]byte, error) {
	b, err := fs.ReadFile(root.FS(), name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return b, nil
}

func newKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode key: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, errors.New("key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, errors.New("key cannot be parsed")
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not ECDSA")
	}
	return key, nil
}

func csrFor(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return der, nil
}

func poolFromPEM(caPEM []byte) (*x509.CertPool, error) {
	b, _ := pem.Decode(caPEM)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("CA is not a PEM certificate")
	}
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil || !ca.IsCA {
		return nil, errors.New("CA certificate is invalid")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, nil
}

func serverName(server string) (string, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil || host == "" {
		return "", errors.New("server must be host:port")
	}
	return host, nil
}

// TLSForRegistration is the client TLS config for registering: TLS 1.3,
// trusting only the pinned CA, no client certificate.
func TLSForRegistration(server string, caPEM []byte) (*tls.Config, error) {
	pool, err := poolFromPEM(caPEM)
	if err != nil {
		return nil, err
	}
	name, err := serverName(server)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: name}, nil
}

// Registrar is the subset of the runner client used to register.
type Registrar interface {
	Register(ctx context.Context, req *runnerv1.RegisterRequest, opts ...grpc.CallOption) (*runnerv1.RegisterResponse, error)
}

// Register exchanges a registration token for an identity and stores it in
// dir. It refuses to overwrite an existing identity.
func Register(ctx context.Context, c Registrar, dir, server string, caPEM []byte, token, name, version string) (*Identity, error) {
	root, err := openState(dir)
	if err != nil {
		return nil, err
	}
	if _, err := root.Stat(metaFile); err == nil {
		_ = root.Close()
		return nil, errors.New("this state directory already holds a registered runner")
	}
	key, keyPEM, err := newKey()
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	csr, err := csrFor(key)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	resp, err := c.Register(ctx, &runnerv1.RegisterRequest{
		ProtocolVersion: ProtocolVersion, RegistrationToken: token, CsrDer: csr, Name: name, Version: version,
	})
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("register: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.GetCertificateDer()})
	m, _ := json.Marshal(meta{RunnerID: resp.GetRunnerId(), Server: server})
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{keyFile, keyPEM, 0o600}, {certFile, certPEM, 0o644}, {caFile, caPEM, 0o644}, {metaFile, m, 0o644}} {
		if err := writeFile(root, f.name, f.data, f.mode); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	_ = root.Close()
	return Load(dir)
}

// Load opens a registered identity.
func Load(dir string) (*Identity, error) {
	root, err := openState(dir)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Identity, error) {
		_ = root.Close()
		return nil, err
	}
	mb, err := readFile(root, metaFile)
	if err != nil {
		return fail(errors.New("runner is not registered (run `kiln-runner register` first)"))
	}
	var m meta
	if err := json.Unmarshal(mb, &m); err != nil || m.RunnerID == "" || m.Server == "" {
		return fail(errors.New("runner.json is invalid"))
	}
	caPEM, err := readFile(root, caFile)
	if err != nil {
		return fail(err)
	}
	pool, err := poolFromPEM(caPEM)
	if err != nil {
		return fail(err)
	}
	id := &Identity{root: root, runnerID: m.RunnerID, server: m.Server, caPool: pool}
	id.finishInterruptedRenewal()
	if err := id.loadCert(); err != nil {
		return fail(err)
	}
	return id, nil
}

// Close releases the state directory.
func (id *Identity) Close() error { return id.root.Close() } //nolint:wrapcheck // trivial

// finishInterruptedRenewal completes a renewal that crashed after the new
// certificate was written but before the pending key was installed.
func (id *Identity) finishInterruptedRenewal() {
	pending, err := readFile(id.root, pendingKeyFile)
	if err != nil {
		return
	}
	certPEM, err := readFile(id.root, certFile)
	if err != nil {
		return
	}
	if _, err := tls.X509KeyPair(certPEM, pending); err == nil {
		_ = id.root.Rename(pendingKeyFile, keyFile)
	}
}

func (id *Identity) loadCert() error {
	keyPEM, err := readFile(id.root, keyFile)
	if err != nil {
		return err
	}
	certPEM, err := readFile(id.root, certFile)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("certificate and key do not match")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	id.mu.Lock()
	id.cert, id.leaf = cert, leaf
	id.mu.Unlock()
	return nil
}

// ClientTLS is the mTLS config for runner calls. It presents the current
// certificate on every new handshake, so a renewal takes effect on the next
// connection.
func (id *Identity) ClientTLS() (*tls.Config, error) {
	name, err := serverName(id.server)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    id.caPool,
		ServerName: name,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			id.mu.Lock()
			defer id.mu.Unlock()
			c := id.cert
			return &c, nil
		},
	}, nil
}

// NotAfter returns the current certificate's expiry.
func (id *Identity) NotAfter() time.Time {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.leaf.NotAfter
}

// NeedsRenewal reports whether the certificate is past half its lifetime,
// or a previous renewal was interrupted.
func (id *Identity) NeedsRenewal(now time.Time) bool {
	if _, err := id.root.Stat(pendingKeyFile); err == nil {
		return true
	}
	id.mu.Lock()
	defer id.mu.Unlock()
	life := id.leaf.NotAfter.Sub(id.leaf.NotBefore)
	return now.After(id.leaf.NotBefore.Add(life / 2))
}

// Renewer is the subset of the runner client used to renew.
type Renewer interface {
	RenewCertificate(ctx context.Context, req *runnerv1.RenewCertificateRequest, opts ...grpc.CallOption) (*runnerv1.RenewCertificateResponse, error)
}

// Renew obtains a new certificate for a new key. The key is persisted
// before the request so an interrupted renewal is retried with it.
func (id *Identity) Renew(ctx context.Context, c Renewer) error {
	var key *ecdsa.PrivateKey
	if pending, err := readFile(id.root, pendingKeyFile); err == nil {
		if key, err = parseKey(pending); err != nil {
			return fmt.Errorf("pending key: %w", err)
		}
	} else {
		var keyPEM []byte
		if key, keyPEM, err = newKey(); err != nil {
			return err
		}
		if err := writeFile(id.root, pendingKeyFile, keyPEM, 0o600); err != nil {
			return err
		}
	}
	csr, err := csrFor(key)
	if err != nil {
		return err
	}
	resp, err := c.RenewCertificate(ctx, &runnerv1.RenewCertificateRequest{ProtocolVersion: ProtocolVersion, CsrDer: csr})
	if err != nil {
		return fmt.Errorf("renew certificate: %w", err)
	}
	newCert, err := x509.ParseCertificate(resp.GetCertificateDer())
	if err != nil {
		return errors.New("renew certificate: invalid certificate from server")
	}
	if _, err := newCert.Verify(x509.VerifyOptions{Roots: id.caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("renew certificate: certificate not issued by the pinned CA")
	}
	pub, ok := newCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return errors.New("renew certificate: certificate is not for our key")
	}
	if err := writeFile(id.root, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.GetCertificateDer()}), 0o644); err != nil {
		return err
	}
	if err := id.root.Rename(pendingKeyFile, keyFile); err != nil {
		return fmt.Errorf("install renewed key: %w", err)
	}
	return id.loadCert()
}
