package tlsutil

import (
	"crypto/tls"
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

// The vault serves its leaf with its root, and a client of its root and
// its pin takes it.
func TestServedChainVerifies(t *testing.T) {
	d := state.Dir{Path: t.TempDir()}
	if err := d.Create(); err != nil {
		t.Fatal(err)
	}
	if err := Write(d, "127.0.0.1", time.Now()); err != nil {
		t.Fatal(err)
	}
	c, err := Load(d, time.Now)
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

// A leaf with less than renewBefore left is made again from the root when
// the vault loads (and while it serves): the pin - the root's - stays, and
// a machine's client goes on verifying it.
func TestLeafRenewedFromTheRoot(t *testing.T) {
	d := state.Dir{Path: t.TempDir()}
	if err := d.Create(); err != nil {
		t.Fatal(err)
	}
	made := time.Now().AddDate(-1, 0, 10) // the leaf has 10 days left
	if err := Write(d, "127.0.0.1", made); err != nil {
		t.Fatal(err)
	}
	c, err := Load(d, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(c.Leaf().NotAfter); left < 300*24*time.Hour {
		t.Fatalf("the leaf was not made again: %v left", left)
	}
	again, err := Load(d, time.Now)
	if err != nil || again.Pin() != c.Pin() || !again.Leaf().Equal(c.Leaf()) {
		t.Fatalf("the renewed leaf was not kept, or the pin moved: %v", err)
	}
	addr := serveCerts(t, c)
	cfg, _ := ClientConfig("https://"+addr, c.RootPEM(), c.Pin())
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("the renewed leaf: %v", err)
	}
	conn.Close()
	if renewed, err := c.Renew(); err != nil || renewed {
		t.Fatalf("a fresh leaf made again: %v %v", renewed, err)
	}
}

// A state directory of the version before the root says what to do.
func TestLoadWithoutRoot(t *testing.T) {
	d := state.Dir{Path: t.TempDir()}
	if err := d.Create(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d, time.Now); err == nil || !strings.Contains(err.Error(), "init") {
		t.Fatalf("no root: %v", err)
	}
}
