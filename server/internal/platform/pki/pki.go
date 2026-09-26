// SPDX-License-Identifier: Apache-2.0

// Package pki is Kiln's internal runner certificate authority (ADR-0005 §2).
//
// The CA is an ECDSA P-256 key and self-signed certificate kept in a
// directory outside the database (ca.key, mode 0600; ca.crt). It signs the
// runner gRPC server certificate and short-lived runner client
// certificates. Runner identities are set by the server only: a CSR
// contributes its public key and nothing else, and its signature is checked
// as proof of possession. Only the standard library is used.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// File names inside the CA directory.
const (
	CertFile = "ca.crt"
	KeyFile  = "ca.key"
)

// ErrInvalidCSR means a CSR was malformed, badly signed, or used a
// disallowed key type.
var ErrInvalidCSR = errors.New("invalid certificate signing request")

// ErrInvalidIdentity means a certificate does not carry a valid Kiln runner
// identity.
var ErrInvalidIdentity = errors.New("certificate has no valid runner identity")

// CA signs server and runner certificates.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

// Init creates a new CA in dir. It refuses to overwrite an existing key.
func Init(dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("init runner CA: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("init runner CA: %w", err)
	}
	defer func() { _ = root.Close() }()
	if _, err := root.Stat(KeyFile); err == nil {
		return fmt.Errorf("init runner CA: %s already exists", KeyFile)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("init runner CA: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Kiln runner CA", Organization: []string{"Kiln"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("init runner CA: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("init runner CA: %w", err)
	}
	if err := writeNew(root, KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeNew(root, CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeNew(root *os.Root, name string, data []byte, mode os.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// Load reads the CA from dir.
func Load(dir string) (*CA, error) {
	fsys := os.DirFS(dir)
	certPEM, err := fs.ReadFile(fsys, CertFile)
	if err != nil {
		return nil, fmt.Errorf("load runner CA certificate: %w", err)
	}
	keyPEM, err := fs.ReadFile(fsys, KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load runner CA key: %w", err)
	}
	return parse(certPEM, keyPEM)
}

func parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("load runner CA: certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("load runner CA certificate: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		// Never include key material in errors.
		return nil, errors.New("load runner CA: key is not a PEM PKCS#8 private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, errors.New("load runner CA: key could not be parsed")
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("load runner CA: key must be ECDSA P-256")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("load runner CA: key does not match certificate")
	}
	if !cert.IsCA {
		return nil, errors.New("load runner CA: certificate is not a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{cert: cert, key: key, pool: pool}, nil
}

// Pool returns a pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool { return ca.pool }

// CertDER returns the CA certificate.
func (ca *CA) CertDER() []byte { return ca.cert.Raw }

func newSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	b[0] &= 0x7f // keep it positive
	return new(big.Int).SetBytes(b), nil
}

// SerialHex formats a certificate serial the way Kiln stores it.
func SerialHex(n *big.Int) string { return hex.EncodeToString(n.Bytes()) }

// IssueServerCert issues a TLS server certificate for hostnames (DNS names
// or IP addresses) with a fresh key.
func (ca *CA) IssueServerCert(hostnames []string, now time.Time, ttl time.Duration) (tls.Certificate, error) {
	if len(hostnames) == 0 {
		return tls.Certificate{}, errors.New("issue server certificate: no hostnames")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("issue server certificate: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostnames[0]},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hostnames {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("issue server certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("issue server certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// idPattern matches Kiln IDs (ULIDs) embedded in runner identities.
var idPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// Identity is the runner identity carried by a client certificate.
type Identity struct {
	RunnerID string
	OrgID    string
	Serial   string
}

func identityURI(orgID, runnerID string) *url.URL {
	return &url.URL{Scheme: "kiln", Host: "orgs", Path: "/" + orgID + "/runners/" + runnerID}
}

// Issued is a signed runner certificate.
type Issued struct {
	DER      []byte
	Serial   string
	NotAfter time.Time
}

// SignRunnerCSR verifies csrDER's signature (proof of possession) and issues
// a client certificate for its public key whose identity is set entirely by
// the server: CN=runnerID and URI SAN kiln://orgs/<org>/runners/<runner>.
// Every subject field and extension in the CSR is ignored. Only ECDSA P-256
// and Ed25519 keys are accepted.
func (ca *CA) SignRunnerCSR(csrDER []byte, runnerID, orgID string, now time.Time, ttl time.Duration) (Issued, error) {
	if !idPattern.MatchString(runnerID) || !idPattern.MatchString(orgID) {
		return Issued{}, ErrInvalidIdentity
	}
	if len(csrDER) == 0 || len(csrDER) > 8<<10 {
		return Issued{}, ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return Issued{}, ErrInvalidCSR
	}
	if err := csr.CheckSignature(); err != nil {
		return Issued{}, ErrInvalidCSR
	}
	var pub crypto.PublicKey
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return Issued{}, ErrInvalidCSR
		}
		pub = k
	case ed25519.PublicKey:
		pub = k
	default:
		return Issued{}, ErrInvalidCSR
	}
	serial, err := newSerial()
	if err != nil {
		return Issued{}, err
	}
	notAfter := now.Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: runnerID, Organization: []string{"Kiln runner"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identityURI(orgID, runnerID)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		return Issued{}, fmt.Errorf("sign runner certificate: %w", err)
	}
	return Issued{DER: der, Serial: SerialHex(serial), NotAfter: notAfter}, nil
}

// RunnerIdentity extracts and checks the identity of a client certificate
// that the TLS stack has already verified against this CA. The CN and the
// URI SAN must agree, and the certificate must be for client auth.
func RunnerIdentity(cert *x509.Certificate) (Identity, error) {
	if cert == nil || len(cert.URIs) != 1 {
		return Identity{}, ErrInvalidIdentity
	}
	clientAuth := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return Identity{}, ErrInvalidIdentity
	}
	u := cert.URIs[0]
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if u.Scheme != "kiln" || u.Host != "orgs" || len(parts) != 3 || parts[1] != "runners" ||
		!idPattern.MatchString(parts[0]) || !idPattern.MatchString(parts[2]) || cert.Subject.CommonName != parts[2] {
		return Identity{}, ErrInvalidIdentity
	}
	return Identity{RunnerID: parts[2], OrgID: parts[0], Serial: SerialHex(cert.SerialNumber)}, nil
}
