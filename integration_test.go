//go:build integration

package main

import (
	"strings"
	"testing"

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
