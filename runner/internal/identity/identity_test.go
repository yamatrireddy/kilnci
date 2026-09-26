// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	runnerv1 "github.com/yamatrireddy/kilnci/proto/gen/go/kiln/runner/v1"
)

// testCA signs client certificates for whatever key a CSR carries, like the
// Kiln server does.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	ttl  time.Duration
	// failNext makes the next renewal fail after signing (lost response).
	failNext bool
	// wrongKey signs a different key than the CSR's.
	wrongKey bool
	renewals int
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ttl: time.Hour}
}

func (ca *testCA) sign(csrDER []byte, notBefore time.Time) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	pub := csr.PublicKey
	if ca.wrongKey {
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &other.PublicKey
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "runner"},
		NotBefore: notBefore, NotAfter: notBefore.Add(ca.ttl),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
}

func (ca *testCA) Register(_ context.Context, req *runnerv1.RegisterRequest, _ ...grpc.CallOption) (*runnerv1.RegisterResponse, error) {
	if req.GetRegistrationToken() != "kiln_rrt_good" {
		return nil, errors.New("unauthenticated")
	}
	der, err := ca.sign(req.GetCsrDer(), time.Now().Add(-time.Minute))
	if err != nil {
		return nil, err
	}
	return &runnerv1.RegisterResponse{RunnerId: "01K6A7B8C9D0E1F2G3H4J5K6M7", CertificateDer: der, CaCertificateDer: ca.cert.Raw}, nil
}

func (ca *testCA) RenewCertificate(_ context.Context, req *runnerv1.RenewCertificateRequest, _ ...grpc.CallOption) (*runnerv1.RenewCertificateResponse, error) {
	ca.renewals++
	der, err := ca.sign(req.GetCsrDer(), time.Now().Add(-time.Minute))
	if err != nil {
		return nil, err
	}
	if ca.failNext {
		ca.failNext = false
		return nil, errors.New("connection reset")
	}
	return &runnerv1.RenewCertificateResponse{CertificateDer: der}, nil
}

func register(t *testing.T, ca *testCA) (*Identity, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	id, err := Register(t.Context(), ca, dir, "runners.kiln.test:9443", ca.pem, "kiln_rrt_good", "r1", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = id.Close() })
	return id, dir
}

func TestRegisterAndLoad(t *testing.T) {
	ca := newTestCA(t)
	id, dir := register(t, ca)
	if id.RunnerID() != "01K6A7B8C9D0E1F2G3H4J5K6M7" || id.Server() != "runners.kiln.test:9443" {
		t.Fatalf("identity = %s %s", id.RunnerID(), id.Server())
	}
	if _, err := Register(t.Context(), ca, dir, "x:1", ca.pem, "kiln_rrt_good", "r", "1"); err == nil {
		t.Fatal("re-registration overwrote an identity")
	}
	again, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	cfg, err := again.ClientTLS()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "runners.kiln.test" || cfg.MinVersion != 0x0304 || cfg.RootCAs == nil {
		t.Fatalf("tls config = %+v", cfg)
	}
	c, err := cfg.GetClientCertificate(nil)
	if err != nil || len(c.Certificate) == 0 {
		t.Fatalf("client cert = %v", err)
	}
	if again.NeedsRenewal(time.Now()) {
		t.Fatal("fresh certificate needs renewal")
	}
	if !again.NeedsRenewal(time.Now().Add(45 * time.Minute)) {
		t.Fatal("certificate past half-life does not need renewal")
	}
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("unregistered load = %v", err)
	}
}

func TestRegister_BadTokenWritesNothing(t *testing.T) {
	ca := newTestCA(t)
	dir := filepath.Join(t.TempDir(), "state")
	if _, err := Register(t.Context(), ca, dir, "h:1", ca.pem, "kiln_rrt_bad", "r", "1"); err == nil {
		t.Fatal("bad token registered")
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("state written for a failed registration")
	}
}

func TestTLSForRegistration_RequiresPinnedCA(t *testing.T) {
	if _, err := TLSForRegistration("h:1", []byte("not pem")); err == nil {
		t.Fatal("accepted garbage CA")
	}
	ca := newTestCA(t)
	if _, err := TLSForRegistration("no-port", ca.pem); err == nil {
		t.Fatal("accepted server without port")
	}
	cfg, err := TLSForRegistration("h:1", ca.pem)
	if err != nil || cfg.RootCAs == nil || cfg.InsecureSkipVerify {
		t.Fatalf("cfg = %+v %v", cfg, err)
	}
}

func TestRenew_RotatesKeyAndSurvivesALostResponse(t *testing.T) {
	ca := newTestCA(t)
	id, dir := register(t, ca)
	before := id.leaf.SerialNumber

	ca.failNext = true
	if err := id.Renew(t.Context(), ca); err == nil {
		t.Fatal("lost response reported as success")
	}
	if !id.NeedsRenewal(time.Now()) {
		t.Fatal("an interrupted renewal must be retried")
	}
	// The retry must reuse the pending key (the server treats a same-key
	// retry as idempotent and anything else as credential reuse).
	pendingBefore, err := readFile(id.root, pendingKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Renew(t.Context(), ca); err != nil {
		t.Fatal(err)
	}
	keyAfter, _ := readFile(id.root, keyFile)
	if string(keyAfter) != string(pendingBefore) {
		t.Fatal("retry used a different key than the pending one")
	}
	if id.NeedsRenewal(time.Now()) || id.leaf.SerialNumber.Cmp(before) == 0 || id.NotAfter().IsZero() {
		t.Fatalf("renewal did not install a new certificate")
	}
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = reloaded.Close()
}

func TestRenew_RejectsCertificatesForOtherKeysOrCAs(t *testing.T) {
	ca := newTestCA(t)
	id, _ := register(t, ca)
	ca.wrongKey = true
	if err := id.Renew(t.Context(), ca); err == nil || !strings.Contains(err.Error(), "not for our key") {
		t.Fatalf("wrong key = %v", err)
	}
	ca.wrongKey = false
	other := newTestCA(t)
	if err := id.Renew(t.Context(), other); err == nil || !strings.Contains(err.Error(), "pinned CA") {
		t.Fatalf("other CA = %v", err)
	}
}

func TestLoad_FinishesInterruptedRenewal(t *testing.T) {
	ca := newTestCA(t)
	id, dir := register(t, ca)
	// Simulate a crash after cert.pem was written but before the key moved.
	key, keyPEM, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := csrFor(key)
	der, err := ca.sign(csr, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(id.root, pendingKeyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(id.root, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatalf("load after interrupted renewal: %v", err)
	}
	defer func() { _ = reloaded.Close() }()
	if reloaded.NeedsRenewal(time.Now()) {
		t.Fatal("pending key was not installed")
	}
}
