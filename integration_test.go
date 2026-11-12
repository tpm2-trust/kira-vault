//go:build integration

package main

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tpm2-trust/kira/core/vaultproto"

	"github.com/tpm2-trust/kira-vault/internal/approval"
	"github.com/tpm2-trust/kira-vault/internal/state"
	"github.com/tpm2-trust/kira-vault/internal/vaulttest"
)

// The vault on a software TPM: a release; the vault's PCR 23 moves, and every release
// is denied with the advice to approve (the device not held responsible); approved
// with the PIN beside the running serve, releases again. A device enrolled with a
// pepper is approved over the operator interface with it. The TPM is lost: the
// backup restores the master into another, and both are released to as before.
func TestVaultOnSWTPM(t *testing.T) {
	sock := vaulttest.StartSWTPM(t)
	v := initVault(t, "--tpm", sock, "--pcrs", "7,23", "--operator-listen", freePort(t))
	v.start()
	m := v.enrol("db-03")
	wantReleased(t, m, v.release(m))
	alice := v.operator("alice")
	p := v.enrolWith("db-04", true)
	res := approve(t, v, alice, p, `{"pepper":"from the operator"}`)
	wantReleased(t, p, res)
	if got, err := p.OpenPepper(res.Pepper); err != nil || got != "from the operator" {
		t.Fatalf("released pepper %q: %v", got, err)
	}

	vaulttest.ExtendPCR(t, sock, 23, "another boot of the vault")
	for i := 0; i < 6; i++ {
		res := v.release(m)
		if res.Status != vaultproto.StatusDenied || res.Reason != approval.ErrDue.Error() {
			t.Fatalf("after PCR 23 moved: %+v", res)
		}
	}
	d, _ := state.Dir{Path: v.dir}.Devices()
	if len(d) != 2 || d[0].Locked || d[0].Failures != 0 {
		t.Fatalf("the device after the vault's denials: %+v", d)
	}
	if out, err := cli(t, testPIN+"\n", "approve", "--dir", v.dir); err != nil || !strings.Contains(out, "PCR 23  MOVED") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	wantReleased(t, m, v.release(m))
	res = approve(t, v, alice, p, `{"pepper":"from the operator"}`)
	wantReleased(t, p, res)
	v.stop()

	restoreInto(t, v, vaulttest.StartSWTPM(t))
	v.start()
	wantReleased(t, m, v.release(m))
	res = approve(t, v, alice, p, `{"pepper":"from the operator"}`)
	wantReleased(t, p, res)
}

// control on a vault of a software TPM: it prints what the vault is, judged - serve
// answering (here in-process: neither the unit nor a container), the approval in use,
// the machines' port verified against the root, the device - and after the vault's
// PCR moved, the approval due, until approved.
func TestControlOnSWTPM(t *testing.T) {
	sock := vaulttest.StartSWTPM(t)
	v := initVault(t, "--tpm", sock, "--pcrs", "23")
	v.start()
	v.enrol("db-03")
	look := func() string {
		t.Helper()
		out, err := cli(t, "", "control", "--dir", v.dir, "--socket", v.sock)
		if err != nil {
			t.Fatalf("control: %v\n%s", err, out)
		}
		return out
	}
	out := look()
	for _, want := range []string{"serve runs, neither under the unit nor in a container", "approval", "in use", "answers, verified against the root and its pin", "1 enrolled", "Enrol a machine", "kira-vault token create"} {
		if !strings.Contains(out, want) {
			t.Errorf("control lacks %q:\n%s", want, out)
		}
	}
	vaulttest.ExtendPCR(t, sock, 23, "another boot of the vault")
	if out := look(); !strings.Contains(out, "due: PCR 23 moved") {
		t.Fatalf("control after PCR 23 moved:\n%s", out)
	}
	if out, err := cli(t, testPIN+"\n", "approve", "--dir", v.dir); err != nil {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	if out := look(); strings.Contains(out, "due") {
		t.Fatalf("control after the approval:\n%s", out)
	}
}

// The TLS root key is in the vault's TPM alone: the state directory holds no private
// key, and beside another TPM - a copy of it, a backup - it does not serve. The
// master's backup restores the key with the master: the pin holds (TestVaultOnSWTPM
// releases to the machines' unchanged pin after its restore).
func TestStateDirectoryAloneDoesNotServe(t *testing.T) {
	v := initVault(t, "--tpm", vaulttest.StartSWTPM(t), "--pcrs", "23")
	filepath.WalkDir(v.dir, func(path string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			if b, _ := os.ReadFile(path); bytes.Contains(b, []byte("PRIVATE KEY")) {
				t.Errorf("%s holds a private key", path)
			}
		}
		return nil
	})
	for _, name := range []string{"key.pem", "ca-key.pem"} {
		if _, err := os.Stat(filepath.Join(v.dir, "tls", name)); err == nil {
			t.Errorf("tls/%s exists", name)
		}
	}
	d := state.Dir{Path: v.dir}
	cfg, err := d.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.TPM = vaulttest.StartSWTPM(t)
	if err := d.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := serve(ctx, d, io.Discard, nil); err == nil || !strings.Contains(err.Error(), "the TLS root key") {
		t.Fatalf("serve beside another TPM: %v", err)
	}
}
