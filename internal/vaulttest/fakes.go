package vaulttest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/tpm2-trust/kira-vault/internal/approval"
	"github.com/tpm2-trust/kira-vault/internal/keys"
)

// Clock is a clock tests move by hand.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts at a fixed time.
func NewClock() *Clock { return &Clock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)} }

// Now implements the server's clock.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock on.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Keys is the server's DeviceKeys without a TPM: K_dev is HMAC-SHA256 of a master of
// its own, as the TPM's is. ChangeBoot moves the vault's boot state on: no key is made
// until Approve, as with an approval due.
type Keys struct {
	mu     sync.Mutex
	master []byte
	due    bool
	Calls  int
}

// NewKeys makes the fake, approved.
func NewKeys() *Keys {
	m := make([]byte, keys.MasterSize)
	rand.Read(m)
	return &Keys{master: m}
}

// ChangeBoot moves the vault's boot state on: an approval is due.
func (k *Keys) ChangeBoot() { k.mu.Lock(); k.due = true; k.mu.Unlock() }

// Approve approves the vault's boot state as it is.
func (k *Keys) Approve() { k.mu.Lock(); k.due = false; k.mu.Unlock() }

// DeviceKey implements server.DeviceKeys.
func (k *Keys) DeviceKey(id, r []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.Calls++
	if k.due {
		return nil, approval.ErrDue
	}
	return hmacOf(k.master, keys.DeviceKeyInput(id, r)), nil
}

func hmacOf(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// TPM is the vault's TPM without one (approval.TPM): PCRs the test extends, a
// counter, approval keys with their PINs, masters it holds in the clear. Its
// approvals are "signed" with a key of its own, and a derivation checks what the
// TPM checks: the signature, the live PCRs, the counter.
type TPM struct {
	mu      sync.Mutex
	pcrs    map[uint8][]byte
	counter uint64
	defined bool
	pins    map[string][]byte // by the key's Name
	masters map[string][]byte // by the master blob's private part
	roots   map[string]*ecdsa.PrivateKey
	sign    []byte
}

// NewTPM makes the fake, its PCRs zero.
func NewTPM() *TPM {
	s := make([]byte, 32)
	rand.Read(s)
	return &TPM{pcrs: map[uint8][]byte{}, pins: map[string][]byte{}, masters: map[string][]byte{}, roots: map[string]*ecdsa.PrivateKey{}, sign: s}
}

// Extend moves a PCR, as a boot measures.
func (t *TPM) Extend(pcr uint8, data string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := sha256.New()
	h.Write(t.value(pcr))
	d := sha256.Sum256([]byte(data))
	h.Write(d[:])
	t.pcrs[pcr] = h.Sum(nil)
}

func (t *TPM) value(pcr uint8) []byte {
	if v, ok := t.pcrs[pcr]; ok {
		return v
	}
	return make([]byte, sha256.Size)
}

// PCRs implements approval.TPM.
func (t *TPM) PCRs(pcrs []uint8) ([][]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out [][]byte
	for _, p := range pcrs {
		out = append(out, bytes.Clone(t.value(p)))
	}
	return out, nil
}

// Counter implements approval.TPM.
func (t *TPM) Counter() (uint64, []byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counter, []byte("fake counter"), nil
}

// CreateApprovalKey implements approval.TPM: a public area with a Name, the PIN kept.
func (t *TPM) CreateApprovalKey(pin []byte) (*keys.Blob, error) {
	unique := make([]byte, 256)
	rand.Read(unique)
	pub := tpm2.TPMTPublic{
		Type: tpm2.TPMAlgRSA, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{SignEncrypt: true, UserWithAuth: true, FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull}, Scheme: tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull}, KeyBits: 2048,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: unique}),
	}
	b := &keys.Blob{Public: tpm2.Marshal(tpm2.New2B(pub)), Private: []byte("fake")}
	name, err := b.Name()
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.pins[string(name)] = bytes.Clone(pin)
	t.mu.Unlock()
	return b, nil
}

// DefineCounter implements approval.TPM.
func (t *TPM) DefineCounter([][]byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.defined {
		return keys.ErrCounterExists
	}
	t.defined = true
	return nil
}

// ImportMaster implements approval.TPM: the master's real public area, kept in the clear.
func (t *TPM) ImportMaster(master, policy []byte) (*keys.Blob, error) {
	pub, err := keys.MasterPublic(master, policy)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	t.mu.Lock()
	t.masters[string(id)] = bytes.Clone(master)
	t.mu.Unlock()
	return &keys.Blob{Public: tpm2.Marshal(tpm2.New2B(*pub)), Private: id}, nil
}

func (t *TPM) signature(a *keys.Approval) []byte {
	m := hmac.New(sha256.New, t.sign)
	m.Write(a.KeyName)
	m.Write(a.PCRs)
	for _, v := range a.Values {
		m.Write(v)
	}
	binary.Write(m, binary.BigEndian, a.Counter)
	return m.Sum(nil)
}

// Approve implements approval.TPM: a wrong PIN refused, the counter raised.
func (t *TPM) Approve(key *keys.Blob, _ [][]byte, pin []byte, pcrs []uint8) (*keys.Approval, error) {
	name, err := key.Name()
	if err != nil {
		return nil, err
	}
	values, _ := t.PCRs(pcrs)
	t.mu.Lock()
	defer t.mu.Unlock()
	if want, ok := t.pins[string(name)]; !ok || !bytes.Equal(want, pin) {
		return nil, keys.ErrWrongPIN
	}
	t.counter++
	a := &keys.Approval{Time: time.Now().UTC(), KeyName: name, PCRs: append([]uint8{}, pcrs...), Values: values, Counter: t.counter}
	a.Signature = t.signature(a)
	return a, nil
}

// Derive implements approval.TPM: what the TPM checks, then the master's HMAC.
func (t *TPM) Derive(master, _ *keys.Blob, _ [][]byte, a *keys.Approval, data []byte) ([]byte, error) {
	live, _ := t.PCRs(a.PCRs)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !hmac.Equal(a.Signature, t.signature(a)) {
		return nil, keys.ErrNotApproved
	}
	if a.Counter != t.counter {
		return nil, keys.ErrNotApproved
	}
	for i := range live {
		if !bytes.Equal(live[i], a.Values[i]) {
			return nil, keys.ErrNotApproved
		}
	}
	m, ok := t.masters[string(master.Private)]
	if !ok {
		return nil, keys.ErrNotApproved
	}
	return hmacOf(m, data), nil
}

// ImportTLSRoot implements approval.TPM: the root key that follows from master, kept
// in the clear by its blob's ID.
func (t *TPM) ImportTLSRoot(master []byte) (*keys.Blob, error) {
	k, err := keys.TLSRootSoftKey(master)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	t.mu.Lock()
	t.roots[string(id)] = k
	t.mu.Unlock()
	return &keys.Blob{Public: tpm2.Marshal(tpm2.New2B(*keys.TLSRootPublic(&k.PublicKey))), Private: id}, nil
}

// TLSRootSigner implements approval.TPM: only a blob this TPM imported signs.
func (t *TPM) TLSRootSigner(b *keys.Blob) (crypto.Signer, error) {
	if _, err := keys.TLSRootPublicKey(b); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	k, ok := t.roots[string(b.Private)]
	if !ok {
		return nil, errors.New("the TLS root key: loading the object (is this the TPM it was made in?)")
	}
	return k, nil
}

// Masters is how many masters it holds, by their blobs' IDs (hex): a restore adds one.
func (t *TPM) Masters() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for id := range t.masters {
		out = append(out, hex.EncodeToString([]byte(id)))
	}
	return out
}

// Info is the TPM's maker and dictionary-attack state, as keys.TPM reads them.
func (t *TPM) Info() (*keys.Info, error) {
	return &keys.Info{Manufacturer: "FAKE", MaxAuthFail: 32, LockoutInterval: 600}, nil
}
