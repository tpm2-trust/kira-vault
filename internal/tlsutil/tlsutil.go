// Package tlsutil makes and serves the vault's TLS: a root of its own and a
// leaf it signs, and the client's side of it.
//
// The root (20 years) is the vault's identity: machines and operators verify
// the vault's chain against it, and the pin a machine keeps
// (vaultproto.PinOf) is its key. That key is in the vault's TPM
// (keys.ImportTLSRoot: derived from the master, so a restore keeps the pin)
// and signs through a crypto.Signer; only the root's certificate is a file.
//
// The leaf (90 days, the vault's host name or address) is what the vault
// serves, with the root. Its key is Ed25519, made in memory at every start
// and at every renewal, and never written: no TLS private key is in the
// state directory or a backup of it. The leaf is made again once fewer than
// renewBefore are left, so that a vault that runs for years goes on being
// verified, without a machine enrolling again. Its certificate is written
// (tls/cert.pem) for 'control' to show.
package tlsutil

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
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

	"github.com/tpm2-trust/kira/core/vaultproto"

	"github.com/tpm2-trust/kira-vault/internal/state"
)

const (
	rootValidity = 20 // years
	leafValidity = 90 * 24 * time.Hour
	// renewBefore: a leaf with less left is made again from the root.
	renewBefore = 30 * 24 * time.Hour
)

// Write makes the vault's root certificate for host in the state directory,
// signed by rootKey: the root key in the vault's TPM.
func Write(d state.Dir, rootKey crypto.Signer, host string, now time.Time) error {
	serial, err := newSerial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "kira-vault root, " + host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(rootValidity, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootKey.Public(), rootKey)
	if err != nil {
		return fmt.Errorf("signing the vault's root: %w", err)
	}
	return state.WriteFile(d.TLSRootPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newLeaf makes a leaf for host with a key of its own, in memory, signed by
// the root; its certificate alone is stored.
func newLeaf(d state.Dir, root *x509.Certificate, rootKey crypto.Signer, host string, now time.Time) (*tls.Certificate, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
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
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, pub, rootKey)
	if err != nil {
		return nil, fmt.Errorf("signing the TLS leaf: %w", err)
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

// Certs is the vault's TLS as it serves it: the root, the signer of its key,
// and the leaf, made again when it is due.
type Certs struct {
	d       state.Dir
	root    *x509.Certificate
	rootKey crypto.Signer
	host    string
	now     func() time.Time

	mu   sync.Mutex
	leaf *tls.Certificate
}

// Load reads the vault's root from the state directory and makes a leaf for
// host with a new key. rootKey must be the key the root certifies: a state
// directory under another TPM's key, or another master's, does not serve.
func Load(d state.Dir, rootKey crypto.Signer, host string, now func() time.Time) (*Certs, error) {
	root, err := readCert(d.TLSRootPath())
	if err != nil {
		return nil, fmt.Errorf("the vault's root: %w (a state directory of an earlier version: make it again with init)", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(rootKey.Public())
	if err != nil {
		return nil, fmt.Errorf("the vault's root key: %w", err)
	}
	if !bytes.Equal(spki, root.RawSubjectPublicKeyInfo) {
		return nil, errors.New("the root key in the TPM is not the key of the vault's root certificate (tls/ca.pem): the state directory and the master do not belong together")
	}
	leaf, err := newLeaf(d, root, rootKey, host, now())
	if err != nil {
		return nil, err
	}
	return &Certs{d: d, root: root, rootKey: rootKey, host: host, now: now, leaf: leaf}, nil
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// Renew makes the leaf again, with a new key, when fewer than renewBefore
// are left, and says whether it did.
func (c *Certs) Renew() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.leaf.Leaf.NotAfter.Sub(now) > renewBefore {
		return false, nil
	}
	leaf, err := newLeaf(c.d, c.root, c.rootKey, c.host, now)
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

// Root is the root's certificate.
func (c *Certs) Root() *x509.Certificate { return c.root }

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
