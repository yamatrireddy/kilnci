// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	runnerID = "01K6A7B8C9D0E1F2G3H4J5K6M7"
	orgID    = "01K6A7B8C9D0E1F2G3H4J5K6M8"
)

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) (*CA, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	if err := Init(dir, now); err != nil {
		t.Fatal(err)
	}
	ca, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ca, dir
}

func csrFor(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestInit_RefusesOverwriteAndLoadRoundTrips(t *testing.T) {
	ca, dir := newCA(t)
	if err := Init(dir, now); err == nil {
		t.Fatal("Init overwrote an existing CA")
	}
	if !ca.cert.IsCA || ca.cert.NotAfter.Before(now.AddDate(9, 0, 0)) {
		t.Fatalf("CA cert = %+v", ca.cert)
	}
	if len(ca.CertDER()) == 0 || ca.Pool() == nil {
		t.Fatal("missing CA material")
	}
}

func TestLoad_RejectsBadMaterial(t *testing.T) {
	_, dir := newCA(t)
	_, other := newCA(t)
	mismatch := t.TempDir()
	copyFile(t, filepath.Join(dir, CertFile), filepath.Join(mismatch, CertFile))
	copyFile(t, filepath.Join(other, KeyFile), filepath.Join(mismatch, KeyFile))
	if _, err := Load(mismatch); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key err = %v", err)
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("empty dir loaded")
	}
	garbage := t.TempDir()
	copyFile(t, filepath.Join(dir, CertFile), filepath.Join(garbage, CertFile))
	if err := os.WriteFile(filepath.Join(garbage, KeyFile), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(garbage); err == nil || strings.Contains(err.Error(), "AAAA") {
		t.Fatalf("garbage key err = %v", err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(filepath.Dir(from)), filepath.Base(from))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSignRunnerCSR_ServerSetsIdentity(t *testing.T) {
	ca, _ := newCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// The CSR asks for another identity, a CA bit, and a server name: all ignored.
	evil := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "01K6A7B8C9D0E1F2G3H4J5K6M9"},
		DNSNames: []string{"kiln.example.com"},
		URIs:     []*url.URL{{Scheme: "kiln", Host: "orgs", Path: "/01K6A7B8C9D0E1F2G3H4J5K6M9/runners/01K6A7B8C9D0E1F2G3H4J5K6M9"}},
	}
	iss, err := ca.SignRunnerCSR(csrFor(t, key, evil), runnerID, orgID, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(iss.DER)
	if err != nil {
		t.Fatal(err)
	}
	if cert.IsCA || len(cert.DNSNames) != 0 || cert.Subject.CommonName != runnerID {
		t.Fatalf("CSR fields leaked into the certificate: %+v", cert)
	}
	id, err := RunnerIdentity(cert)
	if err != nil || id.RunnerID != runnerID || id.OrgID != orgID || id.Serial != iss.Serial {
		t.Fatalf("identity = %+v %v", id, err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify client cert: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("runner cert must not be usable as a server cert")
	}
	if !iss.NotAfter.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("NotAfter = %v", iss.NotAfter)
	}
}

func TestSignRunnerCSR_Rejects(t *testing.T) {
	ca, _ := newCA(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)

	good := csrFor(t, ec, nil)
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-5] ^= 0xff

	cases := map[string]struct {
		csr         []byte
		runner, org string
		want        error
	}{
		"rsa key":       {csrFor(t, rsaKey, nil), runnerID, orgID, ErrInvalidCSR},
		"p384 key":      {csrFor(t, p384, nil), runnerID, orgID, ErrInvalidCSR},
		"bad signature": {tampered, runnerID, orgID, ErrInvalidCSR},
		"garbage":       {[]byte("not a csr"), runnerID, orgID, ErrInvalidCSR},
		"empty":         {nil, runnerID, orgID, ErrInvalidCSR},
		"oversized":     {make([]byte, 9<<10), runnerID, orgID, ErrInvalidCSR},
		"bad runner id": {good, "../x", orgID, ErrInvalidIdentity},
		"bad org id":    {good, runnerID, "org", ErrInvalidIdentity},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ca.SignRunnerCSR(c.csr, c.runner, c.org, now, time.Hour); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	if _, err := ca.SignRunnerCSR(csrFor(t, edKey, nil), runnerID, orgID, now, time.Hour); err != nil {
		t.Fatalf("ed25519 CSR rejected: %v", err)
	}
}

func TestRunnerIdentity_RejectsForgedShapes(t *testing.T) {
	ca, _ := newCA(t)
	mk := func(cn string, uris []*url.URL, eku []x509.ExtKeyUsage) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := newSerial()
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: now, NotAfter: now.Add(time.Hour), URIs: uris, ExtKeyUsage: eku}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	good := identityURI(orgID, runnerID)
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cases := map[string]*x509.Certificate{
		"cn mismatch":    mk("01K6A7B8C9D0E1F2G3H4J5K6M9", []*url.URL{good}, client),
		"no uri":         mk(runnerID, nil, client),
		"two uris":       mk(runnerID, []*url.URL{good, good}, client),
		"server eku":     mk(runnerID, []*url.URL{good}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}),
		"wrong scheme":   mk(runnerID, []*url.URL{{Scheme: "https", Host: "orgs", Path: good.Path}}, client),
		"path traversal": mk(runnerID, []*url.URL{{Scheme: "kiln", Host: "orgs", Path: "/" + orgID + "/runners/../" + runnerID}}, client),
	}
	for name, c := range cases {
		if _, err := RunnerIdentity(c); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := RunnerIdentity(nil); !errors.Is(err, ErrInvalidIdentity) {
		t.Error("nil cert accepted")
	}
}

func TestIssueServerCert(t *testing.T) {
	ca, _ := newCA(t)
	cert, err := ca.IssueServerCert([]string{"runners.kiln.test", "10.0.0.5"}, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.DNSNames[0] != "runners.kiln.test" || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Fatalf("SANs = %v %v", cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "runners.kiln.test", CurrentTime: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueServerCert(nil, now, time.Hour); err == nil {
		t.Fatal("issued a server cert with no hostnames")
	}
}
