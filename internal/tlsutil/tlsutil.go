// Package tlsutil makes and serves the vault's TLS: a root of its own and a
// leaf it signs, and the client's side of it.
//
// The root (ECDSA P-256, 20 years) is the vault's identity: machines and
// operators verify the vault's chain against it, and the pin a machine
// keeps (vaultproto.PinOf) is its key. The leaf (1 year, the vault's host
// name or address) is what the vault serves, with the root; it is made
// again from the root once fewer than renewBefore are left - at start and
// while serving - so that a vault running for a year goes on being
// verified, without a machine enrolling again.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/tpm2-trust/tpm2-kira/core/vaultproto"

	"github.com/tpm2-trust/tpm2-kira-vault/internal/state"
)

const (
	rootValidity = 20 // years
	leafValidity = 1  // year
	// renewBefore: a leaf with less left is made again from the root.
	renewBefore = 30 * 24 * time.Hour
)

// Write makes the vault's root and a leaf for host in the state directory.
func Write(d state.Dir, host string, now time.Time) error {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tpm2-kira-vault root, " + host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(rootValidity, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return err
	}
	if err := state.WriteFile(d.TLSRootKeyPath(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})); err != nil {
		return err
	}
	if err := state.WriteFile(d.TLSRootPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return err
	}
	_, err = writeLeaf(d, root, rootKey, host, now)
	return err
}

// writeLeaf makes a leaf for host, signed by the root, and stores it.
func writeLeaf(d state.Dir, root *x509.Certificate, rootKey *ecdsa.PrivateKey, host string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(leafValidity, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := state.WriteFile(d.TLSKeyPath(), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})); err != nil {
		return nil, err
	}
	if err := state.WriteFile(d.TLSCertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// Certs is the vault's TLS as it serves it: the root, its key, and the
// leaf, made again when it is due.
type Certs struct {
	d       state.Dir
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	now     func() time.Time

	mu   sync.Mutex
	leaf *tls.Certificate
}

// Load reads the vault's TLS from the state directory and makes the leaf
// again when it is due (Renew).
func Load(d state.Dir, now func() time.Time) (*Certs, error) {
	root, err := readCert(d.TLSRootPath())
	if err != nil {
		return nil, fmt.Errorf("the vault's root: %w (a state directory of an earlier version: make it again with init)", err)
	}
	b, err := os.ReadFile(d.TLSRootKeyPath())
	if err != nil {
		return nil, fmt.Errorf("the vault's root key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("the vault's root key is not PEM")
	}
	rootKey, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the vault's root key: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(d.TLSCertPath(), d.TLSKeyPath())
	if err != nil {
		return nil, fmt.Errorf("the TLS key: %w", err)
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, err
	}
	cert.Certificate = append(cert.Certificate[:1], root.Raw)
	c := &Certs{d: d, root: root, rootKey: rootKey, now: now, leaf: &cert}
	if _, err := c.Renew(); err != nil {
		return nil, err
	}
	return c, nil
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s holds no certificate", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

// Renew makes the leaf again from the root when fewer than renewBefore are
// left, for the same name or address, and says whether it did.
func (c *Certs) Renew() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.leaf.Leaf.NotAfter.Sub(now) > renewBefore {
		return false, nil
	}
	host := c.leaf.Leaf.Subject.CommonName
	leaf, err := writeLeaf(c.d, c.root, c.rootKey, host, now)
	if err != nil {
		return false, fmt.Errorf("making the TLS leaf again: %w", err)
	}
	c.leaf = leaf
	return true, nil
}

// Pin is the root's pin: what a machine keeps of the vault.
func (c *Certs) Pin() string { return vaultproto.PinOf(c.root.RawSubjectPublicKeyInfo) }

// RootPEM is the root's certificate, for machines and operators.
func (c *Certs) RootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.root.Raw})
}

// Leaf is the leaf served now.
func (c *Certs) Leaf() *x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.leaf.Leaf
}

// ServerConfig is the vault's TLS configuration: TLS 1.3, leaf and root,
// the leaf made again when it is due.
func (c *Certs) ServerConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if _, err := c.Renew(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.leaf, nil
	}}
}

// RootPEMOf reads the root's certificate from the state directory, as
// 'tls root' prints it.
func RootPEMOf(d state.Dir) ([]byte, error) {
	root, err := readCert(d.TLSRootPath())
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), nil
}

// ClientConfig is a client's TLS configuration for the vault at vaultURL:
// the chain to the vault's root (PEM), then the pin - as a machine
// verifies it (vaultproto.ClientConfig).
func ClientConfig(vaultURL string, rootPEM []byte, pin string) (*tls.Config, error) {
	u, err := url.Parse(vaultURL)
	if err != nil {
		return nil, err
	}
	roots, _, err := vaultproto.ParseRoots(rootPEM)
	if err != nil {
		return nil, err
	}
	return vaultproto.ClientConfig(roots, u.Hostname(), pin), nil
}
