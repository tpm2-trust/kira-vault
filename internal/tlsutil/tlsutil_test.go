package tlsutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tpm2-trust/kira-vault/internal/state"
)

func serveCerts(t *testing.T, c *Certs) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", c.ServerConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.(*tls.Conn).Handshake()
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// rootKey is a root key as the vault's TPM holds it, in software.
func rootKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newDir(t *testing.T) state.Dir {
	t.Helper()
	d := state.Dir{Path: t.TempDir()}
	if err := d.Create(); err != nil {
		t.Fatal(err)
	}
	return d
}

// The vault serves its leaf with its root, and a client of its root and
// its pin takes it.
func TestServedChainVerifies(t *testing.T) {
	d, key := newDir(t), rootKey(t)
	if err := Write(d, key, "127.0.0.1", time.Now()); err != nil {
		t.Fatal(err)
	}
	c, err := Load(d, key, "127.0.0.1", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveCerts(t, c)
	cfg, err := ClientConfig("https://"+addr, c.RootPEM(), c.Pin())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("the vault's own root and pin: %v", err)
	}
	conn.Close()
}

// No TLS private key is a file: the state directory's tls/ holds the two
// certificates alone, after a start and after a renewal.
func TestNoPrivateKeyInTheStateDirectory(t *testing.T) {
	d, key := newDir(t), rootKey(t)
	now := time.Now()
	if err := Write(d, key, "127.0.0.1", now); err != nil {
		t.Fatal(err)
	}
	c, err := Load(d, key, "127.0.0.1", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(leafValidity - renewBefore/2)
	if renewed, err := c.Renew(); err != nil || !renewed {
		t.Fatalf("a leaf with less than renewBefore left: %v %v", renewed, err)
	}
	dir := filepath.Dir(d.TLSRootPath())
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatalf("%s holds a private key", e.Name())
		}
	}
	if strings.Join(names, " ") != "ca.pem cert.pem" {
		t.Fatalf("tls/ holds %v", names)
	}
}

// Every start and every renewal makes the leaf again with a new key; the pin
// - the root's - stays, and a machine's client goes on verifying it.
func TestLeafMadeAgainThePinStays(t *testing.T) {
	d, key := newDir(t), rootKey(t)
	now := time.Now()
	clock := func() time.Time { return now }
	if err := Write(d, key, "127.0.0.1", now); err != nil {
		t.Fatal(err)
	}
	c, err := Load(d, key, "127.0.0.1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if renewed, err := c.Renew(); err != nil || renewed {
		t.Fatalf("a fresh leaf made again: %v %v", renewed, err)
	}
	again, err := Load(d, key, "127.0.0.1", clock)
	if err != nil || again.Pin() != c.Pin() || again.Leaf().Equal(c.Leaf()) {
		t.Fatalf("a second start: the pin moved or the leaf's key was kept: %v", err)
	}
	first := c.Leaf()
	now = now.Add(leafValidity - renewBefore/2)
	if renewed, err := c.Renew(); err != nil || !renewed || c.Leaf().Equal(first) {
		t.Fatalf("the leaf was not made again: %v %v", renewed, err)
	}
	addr := serveCerts(t, c)
	cfg, _ := ClientConfig("https://"+addr, c.RootPEM(), c.Pin())
	cfg.Time = clock
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("the renewed leaf: %v", err)
	}
	conn.Close()
}

// A root key that is not the root certificate's does not serve: a state
// directory beside another TPM's key, or another master's.
func TestLoadWithAnotherRootKey(t *testing.T) {
	d := newDir(t)
	if err := Write(d, rootKey(t), "127.0.0.1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d, rootKey(t), "127.0.0.1", time.Now); err == nil || !strings.Contains(err.Error(), "do not belong together") {
		t.Fatalf("another root key: %v", err)
	}
}

// A state directory of the version before the root says what to do.
func TestLoadWithoutRoot(t *testing.T) {
	if _, err := Load(newDir(t), rootKey(t), "127.0.0.1", time.Now); err == nil || !strings.Contains(err.Error(), "init") {
		t.Fatalf("no root: %v", err)
	}
}
