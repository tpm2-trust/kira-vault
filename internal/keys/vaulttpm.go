package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPM is the vault's TPM at Path (a device such as /dev/tpmrm0; a software TPM's
// socket in tests), opened for each operation, one at a time. Every session is
// explicit and flushed on every way out; every object is flushed after its use.
type TPM struct {
	Path string
	mu   sync.Mutex
}

var (
	// ErrWrongPIN is an approval key's PIN the TPM refused; it counts against the
	// TPM's dictionary-attack limit.
	ErrWrongPIN = errors.New("the approval PIN is wrong (the TPM counts it against its dictionary-attack limit)")
	// ErrLockout is a TPM in dictionary-attack lockout: no PIN is taken until it ends.
	ErrLockout = errors.New("the TPM is in dictionary-attack lockout after wrong PINs: wait for it to end")
	// ErrNotApproved is a derivation the TPM refused: the vault's PCRs or the counter
	// are not those of the approval.
	ErrNotApproved = errors.New("the vault's boot state is not the approved one: approve it")
	// ErrCounterExists is an NV index at the counter's handle already.
	ErrCounterExists = fmt.Errorf("the TPM has an NV index at 0x%08X already (a vault's counter): remove it, or restore into another TPM", uint32(CounterHandle))
)

func (t *TPM) with(f func(tp transport.TPM, srk *primary) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	tp, err := Open(t.Path)
	if err != nil {
		return fmt.Errorf("opening the TPM %s: %w", t.Path, err)
	}
	defer tp.Close()
	srk, flush, err := createPrimary(tp)
	if err != nil {
		return err
	}
	defer flush()
	return f(tp, srk)
}

// pinErr maps the TPM's answer to a PIN.
func pinErr(err error) error {
	switch {
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return ErrWrongPIN
	case errors.Is(err, tpm2.TPMRCLockout):
		return ErrLockout
	}
	return err
}

// salted is an HMAC session salted with the storage primary, the command's first
// parameter encrypted: what travels to the TPM is not on the bus in the clear.
func salted(srk *primary, opts ...tpm2.AuthOption) tpm2.Session {
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, append([]tpm2.AuthOption{tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(srk.handle, srk.public)}, opts...)...)
}

// ImportMaster imports master under the storage primary, its policy authPolicy: the
// duplicate is wrapped for the primary's public key (an outer wrapper, its seed
// encapsulated to that key), so it is not on the bus in the clear. The blob is
// master.json's.
func (t *TPM) ImportMaster(master, authPolicy []byte) (*Blob, error) {
	pub, err := MasterPublic(master, authPolicy)
	if err != nil {
		return nil, err
	}
	sens, err := masterSensitive(master)
	if err != nil {
		return nil, err
	}
	defer Wipe(sens)
	return t.importObject(pub, sens, "the master")
}

// importObject imports an object made outside the TPM under the storage primary: its
// sensitive area sens wrapped for the primary's public key (an outer wrapper, its
// seed encapsulated to that key).
func (t *TPM) importObject(pub *tpm2.TPMTPublic, sens []byte, what string) (*Blob, error) {
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, err
	}
	var blob *Blob
	err = t.with(func(tp transport.TPM, srk *primary) error {
		ek, err := tpm2.ImportEncapsulationKey(&srk.public)
		if err != nil {
			return err
		}
		dup, seed, err := tpm2.CreateDuplicate(rand.Reader, ek, name.Buffer, sens)
		if err != nil {
			return fmt.Errorf("wrapping %s for the TPM: %w", what, err)
		}
		rsp, err := tpm2.Import{
			ParentHandle: tpm2.AuthHandle{Handle: srk.handle, Name: srk.name, Auth: tpm2.PasswordAuth(nil)},
			ObjectPublic: tpm2.New2B(*pub),
			Duplicate:    tpm2.TPM2BPrivate{Buffer: dup},
			InSymSeed:    tpm2.TPM2BEncryptedSecret{Buffer: seed},
			Symmetric:    tpm2.TPMTSymDef{Algorithm: tpm2.TPMAlgNull},
		}.Execute(tp)
		if err != nil {
			return fmt.Errorf("importing %s: %w", what, err)
		}
		blob = &Blob{Public: tpm2.Marshal(tpm2.New2B(*pub)), Private: tpm2.Marshal(rsp.OutPrivate)}
		return nil
	})
	return blob, err
}

// rsaBits is the longest RSA key the TPM takes, of those the workspace's rule asks
// for (TPM2_TestParms: swtpm takes 3072, many TPMs 2048).
func rsaBits(tp transport.TPM) (tpm2.TPMKeyBits, error) {
	for _, bits := range []tpm2.TPMKeyBits{4096, 3072, 2048} {
		_, err := tpm2.TestParms{Parameters: tpm2.TPMTPublicParms{
			Type: tpm2.TPMAlgRSA,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
				KeyBits:   bits,
			}),
		}}.Execute(tp)
		if err == nil {
			return bits, nil
		}
	}
	return 0, errors.New("the TPM takes no RSA key of 2048 bits or more")
}

// CreateApprovalKey creates the approval key under the storage primary: an
// unrestricted RSA signing key (RSASSA-SHA256) of the longest length the TPM takes,
// fixed to this TPM, its authValue the PIN, dictionary-attack protected. The PIN
// travels encrypted (a salted session); the caller wipes it. The blob is
// approval-key.json's.
func (t *TPM) CreateApprovalKey(pin []byte) (*Blob, error) {
	if len(pin) == 0 {
		return nil, errors.New("an approval key without a PIN")
	}
	var blob *Blob
	err := t.with(func(tp transport.TPM, srk *primary) error {
		bits, err := rsaBits(tp)
		if err != nil {
			return err
		}
		rsp, err := tpm2.Create{
			ParentHandle: tpm2.AuthHandle{Handle: srk.handle, Name: srk.name, Auth: salted(srk)},
			InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: pin},
			}},
			InPublic: tpm2.New2B(tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
					SignEncrypt:         true,
				},
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
					Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
					Scheme: tpm2.TPMTRSAScheme{
						Scheme:  tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
					},
					KeyBits: bits,
				}),
			}),
		}.Execute(tp)
		if err != nil {
			return fmt.Errorf("creating the approval key: %w", err)
		}
		blob = &Blob{Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate)}
		return nil
	})
	return blob, err
}

// load loads b under the storage primary; flush unloads it.
func load(tp transport.TPM, srk *primary, b *Blob) (tpm2.NamedHandle, func(), error) {
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("the object's public area: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("the object's private area: %w", err)
	}
	rsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: srk.handle, Name: srk.name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    *priv,
		InPublic:     *pub,
	}.Execute(tp)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("loading the object (is this the TPM it was made in?): %w", err)
	}
	return tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}, func() { tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(tp) }, nil
}

// sign signs digest with the approval key (its PIN through a salted HMAC session).
func sign(tp transport.TPM, srk *primary, key tpm2.NamedHandle, pin, digest []byte) (*tpm2.TPMTSignature, error) {
	rsp, err := tpm2.Sign{
		KeyHandle:  tpm2.AuthHandle{Handle: key.Handle, Name: key.Name, Auth: salted(srk, tpm2.Auth(pin))},
		Digest:     tpm2.TPM2BDigest{Buffer: digest},
		InScheme:   tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
	}.Execute(tp)
	if err != nil {
		return nil, pinErr(err)
	}
	return &rsp.Signature, nil
}

// DefineCounter defines the counter for the approval keys (their Names): an NV
// counter at CounterHandle, readable without authorisation, raised only with one of
// the keys (PolicySigned), noDA. It is not yet written: the first approval raises it.
func (t *TPM) DefineCounter(keyNames [][]byte) error {
	pub, err := counterPublic(keyNames, false)
	if err != nil {
		return err
	}
	return t.with(func(tp transport.TPM, srk *primary) error {
		if _, err := (tpm2.NVReadPublic{NVIndex: CounterHandle}).Execute(tp); err == nil {
			return ErrCounterExists
		}
		_, err := tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			PublicInfo: tpm2.New2B(*pub),
		}.Execute(tp)
		if errors.Is(err, tpm2.TPMRCNVDefined) {
			return ErrCounterExists
		}
		if err != nil {
			return fmt.Errorf("defining the counter (does the owner hierarchy have a password?): %w", err)
		}
		return nil
	})
}

// readCounter is the counter's value and Name; an unwritten counter is 0.
func readCounter(tp transport.TPM) (uint64, []byte, error) {
	pub, err := tpm2.NVReadPublic{NVIndex: CounterHandle}.Execute(tp)
	if err != nil {
		return 0, nil, fmt.Errorf("the vault's counter at 0x%08X: %w", uint32(CounterHandle), err)
	}
	nv, err := pub.NVPublic.Contents()
	if err != nil {
		return 0, nil, err
	}
	if !nv.Attributes.Written {
		return 0, pub.NVName.Buffer, nil
	}
	rsp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: CounterHandle, Name: pub.NVName, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: CounterHandle, Name: pub.NVName},
		Size:       8,
	}.Execute(tp)
	if err != nil {
		return 0, nil, fmt.Errorf("reading the vault's counter: %w", err)
	}
	return binary.BigEndian.Uint64(rsp.Data.Buffer), pub.NVName.Buffer, nil
}

// Counter is the counter's value now and its Name.
func (t *TPM) Counter() (uint64, []byte, error) {
	var n uint64
	var name []byte
	err := t.with(func(tp transport.TPM, _ *primary) error {
		var err error
		n, name, err = readCounter(tp)
		return err
	})
	return n, name, err
}

// raiseCounter raises the counter with the approval key: PolicySigned over the
// session's nonce, then PolicyCommandCode(NV_Increment), then - for several keys -
// PolicyOR of their branches.
func raiseCounter(tp transport.TPM, srk *primary, key tpm2.NamedHandle, keyNames [][]byte, pin []byte) error {
	pub, err := tpm2.NVReadPublic{NVIndex: CounterHandle}.Execute(tp)
	if err != nil {
		return fmt.Errorf("the vault's counter at 0x%08X: %w", uint32(CounterHandle), err)
	}
	sess, closeSess, err := tpm2.PolicySession(tp, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return fmt.Errorf("starting the counter's session: %w", err)
	}
	defer closeSess()
	nonce := sess.NonceTPM()
	h := sha256.New() // aHash = H(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef)
	h.Write(nonce.Buffer)
	binary.Write(h, binary.BigEndian, int32(0))
	h.Write([]byte(counterRef))
	sig, err := sign(tp, srk, key, pin, h.Sum(nil))
	if err != nil {
		return err
	}
	if _, err := (tpm2.PolicySigned{
		PolicySession: sess.Handle(),
		AuthObject:    key,
		NonceTPM:      nonce,
		PolicyRef:     tpm2.TPM2BNonce{Buffer: []byte(counterRef)},
		Auth:          *sig,
	}).Execute(tp); err != nil {
		return fmt.Errorf("PolicySigned for the counter: %w", err)
	}
	if _, err := (tpm2.PolicyCommandCode{PolicySession: sess.Handle(), Code: tpm2.TPMCCNVIncrement}).Execute(tp); err != nil {
		return err
	}
	if len(keyNames) > 1 {
		if _, err := (tpm2.PolicyOr{PolicySession: sess.Handle(), PHashList: counterBranchList(keyNames)}).Execute(tp); err != nil {
			return err
		}
	}
	if _, err := (tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{Handle: CounterHandle, Name: pub.NVName, Auth: sess},
		NVIndex:    tpm2.NamedHandle{Handle: CounterHandle, Name: pub.NVName},
	}).Execute(tp); err != nil {
		return fmt.Errorf("raising the counter (is it this approval key's?): %w", err)
	}
	return nil
}

// readPCRs is the live SHA-256 values of pcrs.
func readPCRs(tp transport.TPM, pcrs []uint8) ([][]byte, error) {
	var out [][]byte
	for _, i := range pcrs { // one at a time: PCR_Read answers at most eight
		rsp, err := tpm2.PCRRead{PCRSelectionIn: pcrSelection([]uint8{i})}.Execute(tp)
		if err != nil {
			return nil, fmt.Errorf("reading PCR %d: %w", i, err)
		}
		if len(rsp.PCRValues.Digests) != 1 {
			return nil, fmt.Errorf("the TPM has no SHA-256 PCR %d", i)
		}
		out = append(out, rsp.PCRValues.Digests[0].Buffer)
	}
	return out, nil
}

// PCRs is the live SHA-256 values of pcrs.
func (t *TPM) PCRs(pcrs []uint8) ([][]byte, error) {
	var v [][]byte
	err := t.with(func(tp transport.TPM, _ *primary) error {
		var err error
		v, err = readPCRs(tp, pcrs)
		return err
	})
	return v, err
}

// Approval is an approval of the vault's boot state: approvals/<time>.json.
type Approval struct {
	Time      time.Time `json:"time"`
	KeyName   []byte    `json:"key_name"` // the approval key that signed it
	PCRs      []uint8   `json:"pcrs"`
	Values    [][]byte  `json:"values"`
	Counter   uint64    `json:"counter"`
	Signature []byte    `json:"signature"` // TPMT_SIGNATURE over ApprovalDigest
}

func (a *Approval) approved() *Approved {
	return &Approved{PCRs: a.PCRs, Values: a.Values, Counter: a.Counter}
}

// Approve approves the vault's boot state as it is: it raises the counter - so that
// every earlier approval fails in the TPM - and signs, with the approval key behind
// pin, the policy over the live values of pcrs and the counter's new value. keyNames
// are every approval key's, in the order of the counter's policy. What moved and
// whether it may be approved (Secure Boot, the encrypted volume) is the caller's to
// have checked. The caller wipes pin.
func (t *TPM) Approve(key *Blob, keyNames [][]byte, pin []byte, pcrs []uint8) (*Approval, error) {
	var a *Approval
	err := t.with(func(tp transport.TPM, srk *primary) error {
		k, flush, err := load(tp, srk, key)
		if err != nil {
			return err
		}
		defer flush()
		values, err := readPCRs(tp, pcrs)
		if err != nil {
			return err
		}
		if err := raiseCounter(tp, srk, k, keyNames, pin); err != nil {
			return err
		}
		n, counterName, err := readCounter(tp)
		if err != nil {
			return err
		}
		ap := &Approval{Time: time.Now().UTC(), KeyName: k.Name.Buffer, PCRs: append([]uint8{}, pcrs...), Values: values, Counter: n}
		policy, err := ApprovedPolicy(ap.approved(), counterName)
		if err != nil {
			return err
		}
		sig, err := sign(tp, srk, k, pin, ApprovalDigest(policy))
		if err != nil {
			return err
		}
		ap.Signature = tpm2.Marshal(sig)
		a = ap
		return nil
	})
	return a, err
}

// Derive is TPM2_HMAC(master, data) under the approval a, for the master's approval
// keys keyNames (their order the PolicyOR's): the TPM checks the approval's
// signature, its PCRs and its counter against the live ones, and the answer comes
// back encrypted (a salted session). The caller wipes it.
func (t *TPM) Derive(master, key *Blob, keyNames [][]byte, a *Approval, data []byte) ([]byte, error) {
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](a.Signature)
	if err != nil {
		return nil, fmt.Errorf("the approval's signature: %w", err)
	}
	keyName, err := key.Name()
	if err != nil {
		return nil, err
	}
	known := false
	for _, n := range keyNames {
		known = known || string(n) == string(keyName)
	}
	if !known {
		return nil, errors.New("the approval key is not one of the master's")
	}
	var outHMAC []byte
	err = t.with(func(tp transport.TPM, srk *primary) error {
		_, counterName, err := readCounter(tp)
		if err != nil {
			return err
		}
		policy, err := ApprovedPolicy(a.approved(), counterName)
		if err != nil {
			return err
		}
		k, flushKey, err := load(tp, srk, key)
		if err != nil {
			return err
		}
		defer flushKey()
		ticket, err := tpm2.VerifySignature{KeyHandle: k, Digest: tpm2.TPM2BDigest{Buffer: ApprovalDigest(policy)}, Signature: *sig}.Execute(tp)
		if err != nil {
			return fmt.Errorf("the approval's signature does not verify: %w", err)
		}
		m, flushMaster, err := load(tp, srk, master)
		if err != nil {
			return err
		}
		defer flushMaster()
		sess, closeSess, err := tpm2.PolicySession(tp, tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(srk.handle, srk.public))
		if err != nil {
			return fmt.Errorf("starting the master's session: %w", err)
		}
		defer closeSess()
		refuse := func(err error) error {
			if errors.Is(err, tpm2.TPMRCPolicyFail) || errors.Is(err, tpm2.TPMRCValue) || errors.Is(err, tpm2.TPMRCPolicy) {
				return ErrNotApproved
			}
			return err
		}
		if _, err := (tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: pcrSelection(a.PCRs)}).Execute(tp); err != nil {
			return refuse(err)
		}
		if _, err := (tpm2.PolicyNV{
			AuthHandle:    tpm2.AuthHandle{Handle: CounterHandle, Name: tpm2.TPM2BName{Buffer: counterName}, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:       counterHandle(counterName),
			PolicySession: sess.Handle(),
			OperandB:      tpm2.TPM2BOperand{Buffer: be64(a.Counter)},
			Operation:     tpm2.TPMEOEq,
		}).Execute(tp); err != nil {
			return refuse(err)
		}
		if _, err := (tpm2.PolicyAuthorize{
			PolicySession:  sess.Handle(),
			ApprovedPolicy: tpm2.TPM2BDigest{Buffer: policy},
			PolicyRef:      tpm2.TPM2BDigest{Buffer: []byte(approvalRef)},
			KeySign:        k.Name,
			CheckTicket:    ticket.Validation,
		}).Execute(tp); err != nil {
			return refuse(err)
		}
		if _, err := (tpm2.PolicyCommandCode{PolicySession: sess.Handle(), Code: tpm2.TPMCCHMAC}).Execute(tp); err != nil {
			return err
		}
		if len(keyNames) > 1 {
			if _, err := (tpm2.PolicyOr{PolicySession: sess.Handle(), PHashList: branchList(keyNames)}).Execute(tp); err != nil {
				return refuse(err)
			}
		}
		rsp, err := tpm2.Hmac{
			Handle:  tpm2.AuthHandle{Handle: m.Handle, Name: m.Name, Auth: sess},
			Buffer:  tpm2.TPM2BMaxBuffer{Buffer: data},
			HashAlg: tpm2.TPMAlgSHA256,
		}.Execute(tp)
		if err != nil {
			return refuse(err)
		}
		outHMAC = rsp.OutHMAC.Buffer
		return nil
	})
	return outHMAC, err
}

// DeviceKeyInput is what the master's HMAC makes a machine's key K_dev of (Derive):
// the device ID and the device's r.
func DeviceKeyInput(deviceID, r []byte) []byte {
	return append(append(make([]byte, 0, len(deviceID)+len(r)), deviceID...), r...)
}
