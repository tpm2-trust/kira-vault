// Package approval is the vault's keys at work: the approval of its live boot state,
// whether one is due, and a machine's key K_dev derived under it in the TPM.
package approval

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/state"
)

// TPM is what the vault does in its TPM (keys.TPM; a fake in tests).
type TPM interface {
	PCRs(pcrs []uint8) ([][]byte, error)
	Counter() (uint64, []byte, error)
	CreateApprovalKey(pin []byte) (*keys.Blob, error)
	DefineCounter(keyNames [][]byte) error
	ImportMaster(master, authPolicy []byte) (*keys.Blob, error)
	Approve(key *keys.Blob, keyNames [][]byte, pin []byte, pcrs []uint8) (*keys.Approval, error)
	Derive(master, key *keys.Blob, keyNames [][]byte, a *keys.Approval, data []byte) ([]byte, error)
}

// ErrDue is a vault whose live boot state no approval covers: an operator approves it
// (kira-vault approve) before anything is released.
var ErrDue = errors.New("the vault's own boot state is not approved: an operator approves it (kira-vault approve)")

// Live is the vault's PCRs and its counter now.
type Live struct {
	PCRs    []uint8
	Values  [][]byte
	Counter uint64
}

// ReadLive reads them.
func ReadLive(t TPM, pcrs []uint8) (*Live, error) {
	values, err := t.PCRs(pcrs)
	if err != nil {
		return nil, err
	}
	n, _, err := t.Counter()
	if err != nil {
		return nil, err
	}
	return &Live{PCRs: pcrs, Values: values, Counter: n}, nil
}

// Covers says whether a is of the live state: the same PCRs at the same values, the
// counter at its value. Only then does the TPM take it.
func (l *Live) Covers(a *keys.Approval) bool {
	if a.Counter != l.Counter || !bytes.Equal(a.PCRs, l.PCRs) || len(a.Values) != len(l.Values) {
		return false
	}
	for i := range a.Values {
		if !bytes.Equal(a.Values[i], l.Values[i]) {
			return false
		}
	}
	return true
}

// Moved is the PCRs whose live values differ from a's.
func (l *Live) Moved(a *keys.Approval) []uint8 {
	var out []uint8
	for i, p := range l.PCRs {
		j := bytes.IndexByte(a.PCRs, p)
		if j < 0 || j >= len(a.Values) || !bytes.Equal(a.Values[j], l.Values[i]) {
			out = append(out, p)
		}
	}
	return out
}

// Current is the approval of the live state among approvals (the newest first), or
// ErrDue.
func Current(l *Live, approvals []*keys.Approval) (*keys.Approval, error) {
	for _, a := range approvals {
		if l.Covers(a) {
			return a, nil
		}
	}
	return nil, ErrDue
}

// Keys derives machines' keys: the master of the state directory in the TPM, under
// the approval of the live state.
type Keys struct {
	TPM  TPM
	Dir  state.Dir
	PCRs []uint8
}

// DeviceKey is a machine's K_dev: the master's HMAC of its device ID and r, in the
// TPM, under the approval of the vault's live state; ErrDue when there is none. The
// caller wipes it.
func (k *Keys) DeviceKey(id, r []byte) ([]byte, error) {
	m, err := k.Dir.Master()
	if err != nil {
		return nil, err
	}
	names, err := m.KeyNames()
	if err != nil {
		return nil, err
	}
	live, err := ReadLive(k.TPM, k.PCRs)
	if err != nil {
		return nil, err
	}
	approvals, err := k.Dir.Approvals()
	if err != nil {
		return nil, err
	}
	a, err := Current(live, approvals)
	if err != nil {
		return nil, err
	}
	key, err := keyOf(m, a)
	if err != nil {
		return nil, err
	}
	kdev, err := k.TPM.Derive(&m.Master, key, names, a, keys.DeviceKeyInput(id, r))
	if errors.Is(err, keys.ErrNotApproved) {
		return nil, ErrDue
	}
	return kdev, err
}

// keyOf is the approval key that signed a.
func keyOf(m *state.Master, a *keys.Approval) (*keys.Blob, error) {
	for i := range m.ApprovalKeys {
		if n, err := m.ApprovalKeys[i].Key.Name(); err == nil && bytes.Equal(n, a.KeyName) {
			return &m.ApprovalKeys[i].Key, nil
		}
	}
	return nil, fmt.Errorf("the approval of %s was signed by a key master.json does not name", a.Time)
}
