//go:build integration

package keys_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/vaulttest"
)

// The master on a software TPM: imported, used only under an approval; the TPM's HMAC
// is the master's HMAC; a wrong PIN, a moved PCR and an older approval are refused; a
// new approval of the moved state works; the backup rebuilds the public area.
func TestMasterOnSWTPM(t *testing.T) {
	sock := vaulttest.StartSWTPM(t)
	tpm := &keys.TPM{Path: sock}
	pin := []byte("246810")

	key, err := tpm.CreateApprovalKey(pin)
	if err != nil {
		t.Fatal(err)
	}
	keyName, err := key.Name()
	if err != nil {
		t.Fatal(err)
	}
	names := [][]byte{keyName}
	if err := tpm.DefineCounter(names); err != nil {
		t.Fatal(err)
	}
	if err := tpm.DefineCounter(names); !errors.Is(err, keys.ErrCounterExists) {
		t.Fatalf("a second counter: %v", err)
	}
	policy, err := keys.MasterPolicy(names)
	if err != nil {
		t.Fatal(err)
	}
	master := make([]byte, keys.MasterSize)
	rand.Read(master)
	mb, err := tpm.ImportMaster(master, policy)
	if err != nil {
		t.Fatal(err)
	}

	// The backup.
	if err := keys.CheckBackup(master, mb); err != nil {
		t.Fatalf("the backup: %v", err)
	}
	other := bytes.Clone(master)
	other[0] ^= 1
	if err := keys.CheckBackup(other, mb); !errors.Is(err, keys.ErrNotTheBackup) {
		t.Fatalf("another master as the backup: %v", err)
	}

	// No approval yet: a wrong PIN is refused, and raises nothing.
	if _, err := tpm.Approve(key, names, []byte("000000"), []uint8{7, 15}); !errors.Is(err, keys.ErrWrongPIN) {
		t.Fatalf("a wrong PIN: %v", err)
	}
	if n, _, err := tpm.Counter(); err != nil || n != 0 {
		t.Fatalf("the counter after a wrong PIN: %d %v", n, err)
	}
	a1, err := tpm.Approve(key, names, pin, []uint8{7, 15})
	if err != nil {
		t.Fatal(err)
	}
	data := keys.DeviceKeyInput(bytes.Repeat([]byte{0xD1}, 16), bytes.Repeat([]byte{0x52}, 32))
	k, err := tpm.Derive(mb, key, names, a1, data)
	if err != nil {
		t.Fatalf("derive under the approval: %v", err)
	}
	m := hmac.New(sha256.New, master)
	m.Write(data)
	if !bytes.Equal(k, m.Sum(nil)) {
		t.Fatal("the TPM's HMAC is not the master's")
	}
	_, counterName, err := tpm.Counter()
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := keys.CounterName(names); !bytes.Equal(counterName, want) {
		t.Fatalf("the counter's Name %x, computed %x", counterName, want)
	}

	// The boot state moves: refused until approved again.
	vaulttest.ExtendPCR(t, sock, 15, "a volume opened")
	if _, err := tpm.Derive(mb, key, names, a1, data); !errors.Is(err, keys.ErrNotApproved) {
		t.Fatalf("derive after PCR 15 moved: %v", err)
	}
	a2, err := tpm.Approve(key, names, pin, []uint8{7, 15})
	if err != nil {
		t.Fatal(err)
	}
	if a2.Counter != a1.Counter+1 {
		t.Fatalf("counter %d after %d", a2.Counter, a1.Counter)
	}
	if k2, err := tpm.Derive(mb, key, names, a2, data); err != nil || !bytes.Equal(k2, k) {
		t.Fatalf("derive under the new approval: %v", err)
	}
	// Rollback: an approval of the same state made later makes a2 fail, whatever the PCRs.
	a3, err := tpm.Approve(key, names, pin, []uint8{7, 15})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.Derive(mb, key, names, a2, data); !errors.Is(err, keys.ErrNotApproved) {
		t.Fatalf("an older approval of the same state: %v", err)
	}
	if _, err := tpm.Derive(mb, key, names, a3, data); err != nil {
		t.Fatal(err)
	}
	// A forged approval: the values changed after the signature.
	forged := *a3
	forged.Counter++
	if _, err := tpm.Derive(mb, key, names, &forged, data); err == nil {
		t.Fatal("an approval changed after its signature")
	}
}

// Two approval keys: the master and the counter take either; each one's approval
// derives the same key.
func TestTwoApprovalKeysOnSWTPM(t *testing.T) {
	sock := vaulttest.StartSWTPM(t)
	tpm := &keys.TPM{Path: sock}
	pinA, pinB := []byte("111111"), []byte("222222")
	keyA, err := tpm.CreateApprovalKey(pinA)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := tpm.CreateApprovalKey(pinB)
	if err != nil {
		t.Fatal(err)
	}
	nameA, _ := keyA.Name()
	nameB, _ := keyB.Name()
	names := [][]byte{nameA, nameB}
	if err := tpm.DefineCounter(names); err != nil {
		t.Fatal(err)
	}
	policy, _ := keys.MasterPolicy(names)
	master := make([]byte, keys.MasterSize)
	rand.Read(master)
	mb, err := tpm.ImportMaster(master, policy)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("device")
	aA, err := tpm.Approve(keyA, names, pinA, []uint8{7})
	if err != nil {
		t.Fatal(err)
	}
	kA, err := tpm.Derive(mb, keyA, names, aA, data)
	if err != nil {
		t.Fatal(err)
	}
	aB, err := tpm.Approve(keyB, names, pinB, []uint8{7})
	if err != nil {
		t.Fatal(err)
	}
	kB, err := tpm.Derive(mb, keyB, names, aB, data)
	if err != nil || !bytes.Equal(kA, kB) {
		t.Fatalf("the second key's approval: %v", err)
	}
	if _, err := tpm.Derive(mb, keyA, names, aA, data); !errors.Is(err, keys.ErrNotApproved) {
		t.Fatalf("the first key's older approval after the second's: %v", err)
	}
	// A key's approval named with another key's blob does not verify.
	if _, err := tpm.Derive(mb, keyA, names, aB, data); err == nil {
		t.Fatal("an approval checked against the wrong key")
	}
}
