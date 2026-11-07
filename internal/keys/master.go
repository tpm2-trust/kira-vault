package keys

// The vault's keys: one master, imported into the vault's TPM, from which each
// machine's key is derived in the TPM; the master is used only under an approval of
// the vault's boot state, signed in the same TPM with the approval key, behind its
// PIN; an NV counter closes the way back to an older approval (kira's
// docs/VAULT.md; PLAN.md, "the vault's keys").
//
// This file is what needs no TPM: the policies' digests, the master's public area,
// the backup's check.

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"

	"github.com/tpm2-trust/kira/core/attest"
)

// MasterSize is the master key's size: an HMAC-SHA256 key.
const MasterSize = 32

// CounterHandle is the vault's NV counter: outside kira's range
// (0x01803000-0x01803FFF, which its sweep takes) and aSSH's (0x018029xx).
const CounterHandle = tpm2.TPMHandle(0x01804000)

// The policies' qualifiers: every signature of the approval key is over one of them,
// so that a signature for one use is none for the other.
const (
	approvalRef = "kira-vault/approval/v1" // an approval: PolicyAuthorize of the master
	counterRef  = "kira-vault/counter/v1"  // raising the counter: PolicySigned
	seedInfo    = "kira-vault/master-seed/v1"
)

// Approved is what an approval approves: the vault's PCRs (SHA-256 bank) at their
// values, and the counter at its value.
type Approved struct {
	PCRs    []uint8  // ascending
	Values  [][]byte // one SHA-256 digest per PCR, in the order of PCRs
	Counter uint64
}

func (a *Approved) check() error {
	if len(a.PCRs) == 0 || len(a.PCRs) != len(a.Values) {
		return fmt.Errorf("an approval of %d PCRs with %d values", len(a.PCRs), len(a.Values))
	}
	for i, p := range a.PCRs {
		if p > 23 || i > 0 && a.PCRs[i-1] >= p {
			return fmt.Errorf("the PCRs %v: from 0 to 23, ascending, each once", a.PCRs)
		}
		if len(a.Values[i]) != sha256.Size {
			return fmt.Errorf("PCR %d's value has %d bytes", p, len(a.Values[i]))
		}
	}
	return nil
}

func be64(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

// counterHandle is the counter as a policy names it: its handle and its Name, which
// its attributes (written or not) and its policy are part of.
func counterHandle(name []byte) tpm2.NamedHandle {
	return tpm2.NamedHandle{Handle: CounterHandle, Name: tpm2.TPM2BName{Buffer: name}}
}

// ApprovedPolicy is the approved part of the master's policy:
// PolicyPCR(the PCRs, their values) ; PolicyNV(the counter == Counter).
func ApprovedPolicy(a *Approved, counterName []byte) ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	composite := sha256.New()
	for _, v := range a.Values {
		composite.Write(v)
	}
	return attest.PolicyDigest(
		tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: composite.Sum(nil)}, Pcrs: pcrSelection(a.PCRs)}.Update,
		tpm2.PolicyNV{NVIndex: counterHandle(counterName), OperandB: tpm2.TPM2BOperand{Buffer: be64(a.Counter)}, Operation: tpm2.TPMEOEq}.Update,
	), nil
}

// ApprovalDigest is what the approval key signs for an approved policy: aHash =
// H(approvedPolicy ‖ policyRef), as PolicyAuthorize checks it.
func ApprovalDigest(approvedPolicy []byte) []byte {
	h := sha256.New()
	h.Write(approvedPolicy)
	h.Write([]byte(approvalRef))
	return h.Sum(nil)
}

// branch is the master's policy for one approval key: PolicyAuthorize(the key,
// approvalRef) ; PolicyCommandCode(TPM2_HMAC).
func branch(keyName []byte) []byte {
	return attest.PolicyDigest(
		tpm2.PolicyAuthorize{PolicyRef: tpm2.TPM2BDigest{Buffer: []byte(approvalRef)}, KeySign: tpm2.TPM2BName{Buffer: keyName}}.Update,
		tpm2.PolicyCommandCode{Code: tpm2.TPMCCHMAC}.Update,
	)
}

// MaxApprovalKeys is how many approval keys a master's policy can name: PolicyOR's
// branches.
const MaxApprovalKeys = 8

// MasterPolicy is the master's authPolicy for its approval keys (their Names): one
// key's branch, or the PolicyOR of every key's.
func MasterPolicy(keyNames [][]byte) ([]byte, error) {
	switch n := len(keyNames); {
	case n == 0:
		return nil, errors.New("a master without an approval key")
	case n == 1:
		return branch(keyNames[0]), nil
	case n > MaxApprovalKeys:
		return nil, fmt.Errorf("%d approval keys: at most %d", n, MaxApprovalKeys)
	}
	return attest.PolicyDigest(tpm2.PolicyOr{PHashList: branchList(keyNames)}.Update), nil
}

func branchList(keyNames [][]byte) tpm2.TPMLDigest {
	var l tpm2.TPMLDigest
	for _, k := range keyNames {
		l.Digests = append(l.Digests, tpm2.TPM2BDigest{Buffer: branch(k)})
	}
	return l
}

// counterBranch is the counter's policy for one approval key: PolicySigned(the key,
// counterRef) ; PolicyCommandCode(TPM2_NV_Increment).
func counterBranch(keyName []byte) []byte {
	return attest.PolicyDigest(
		tpm2.PolicySigned{AuthObject: tpm2.NamedHandle{Name: tpm2.TPM2BName{Buffer: keyName}}, PolicyRef: tpm2.TPM2BNonce{Buffer: []byte(counterRef)}}.Update,
		tpm2.PolicyCommandCode{Code: tpm2.TPMCCNVIncrement}.Update,
	)
}

func counterBranchList(keyNames [][]byte) tpm2.TPMLDigest {
	var l tpm2.TPMLDigest
	for _, k := range keyNames {
		l.Digests = append(l.Digests, tpm2.TPM2BDigest{Buffer: counterBranch(k)})
	}
	return l
}

// CounterPolicy is the counter's authPolicy for the approval keys: one key's branch,
// or the PolicyOR of every key's. Only an approval key raises it, so nobody else can
// make the approvals invalid by raising it.
func CounterPolicy(keyNames [][]byte) ([]byte, error) {
	switch n := len(keyNames); {
	case n == 0:
		return nil, errors.New("a counter without an approval key")
	case n == 1:
		return counterBranch(keyNames[0]), nil
	case n > MaxApprovalKeys:
		return nil, fmt.Errorf("%d approval keys: at most %d", n, MaxApprovalKeys)
	}
	return attest.PolicyDigest(tpm2.PolicyOr{PHashList: counterBranchList(keyNames)}.Update), nil
}

// counterPublic is the counter's public area, written or not yet.
func counterPublic(keyNames [][]byte, written bool) (*tpm2.TPMSNVPublic, error) {
	policy, err := CounterPolicy(keyNames)
	if err != nil {
		return nil, err
	}
	return &tpm2.TPMSNVPublic{
		NVIndex: CounterHandle,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			NT:          tpm2.TPMNTCounter,
			PolicyWrite: true,
			AuthRead:    true,
			NoDA:        true,
			Written:     written,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
		DataSize:   8,
	}, nil
}

// CounterName is the counter's Name once written, for the approval keys: what the
// master's approved policies name it by.
func CounterName(keyNames [][]byte) ([]byte, error) {
	pub, err := counterPublic(keyNames, true)
	if err != nil {
		return nil, err
	}
	n, err := tpm2.NVName(pub)
	if err != nil {
		return nil, err
	}
	return n.Buffer, nil
}

// masterSeed is the master's obfuscation value, derived from it: its public area then
// follows from the master alone, and the backup alone rebuilds it (CheckBackup).
func masterSeed(master []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, master, nil, seedInfo, sha256.Size)
}

// MasterPublic is the master's public area under authPolicy: a keyed-hash HMAC-SHA256
// key, sign set, no use by authValue (userWithAuth clear: the policy alone), admin by
// policy, not fixed to a TPM (it existed once, at init, and then only in the backup);
// unique = H(seed ‖ master).
func MasterPublic(master, authPolicy []byte) (*tpm2.TPMTPublic, error) {
	if len(master) != MasterSize {
		return nil, fmt.Errorf("a master of %d bytes, want %d", len(master), MasterSize)
	}
	seed, err := masterSeed(master)
	if err != nil {
		return nil, err
	}
	defer Wipe(seed)
	u := sha256.New()
	u.Write(seed)
	u.Write(master)
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:     true,
			AdminWithPolicy: true,
			NoDA:            true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme:  tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: u.Sum(nil)}),
	}, nil
}

// masterSensitive is the master's sensitive area, marshalled: the caller wipes it.
func masterSensitive(master []byte) ([]byte, error) {
	seed, err := masterSeed(master)
	if err != nil {
		return nil, err
	}
	defer Wipe(seed)
	return tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue:     tpm2.TPM2BDigest{Buffer: seed},
		Sensitive:     tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BSensitiveData{Buffer: master}),
	}), nil
}

// ErrNotTheBackup is a backup that does not rebuild this vault's master.
var ErrNotTheBackup = errors.New("this is not this vault's backup")

// CheckBackup says whether master rebuilds the public area the vault imported
// (master.json's): the public area's unique is H(seed ‖ master), and nothing else of
// the master is kept anywhere.
func CheckBackup(master []byte, m *Blob) error {
	pub, err := m.public()
	if err != nil {
		return err
	}
	rebuilt, err := MasterPublic(master, pub.AuthPolicy.Buffer)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(tpm2.Marshal(tpm2.New2B(*rebuilt)), m.Public) != 1 {
		return ErrNotTheBackup
	}
	return nil
}

// Blob is an object of the vault's TPM, loaded under the storage primary: its
// TPM2B_PUBLIC and its TPM2B_PRIVATE (the master in master.json, the approval key in
// approval-key.json).
type Blob struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

func (b *Blob) public() (*tpm2.TPMTPublic, error) {
	p, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return nil, fmt.Errorf("the object's public area: %w", err)
	}
	return p.Contents()
}

// Name is the object's Name.
func (b *Blob) Name() ([]byte, error) {
	p, err := b.public()
	if err != nil {
		return nil, err
	}
	n, err := tpm2.ObjectName(p)
	if err != nil {
		return nil, err
	}
	return n.Buffer, nil
}
