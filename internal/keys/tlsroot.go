package keys

// The vault's TLS root key: ECDSA P-256, derived from the master and imported into
// the vault's TPM beside it. Nothing of it is in the state directory but the TPM's
// wrapped blob, so a copy of the directory signs no certificate; and a restore of the
// master's backup into another TPM makes the same key again, so the pin every machine
// keeps of the vault (the root's key) holds. It exists outside the TPM where the
// master does: in locked memory at init and at a restore.
//
// ECDSA, not RSA: the key has to follow from the master alone, and the standard
// library makes no RSA key from a seed.

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const tlsRootInfo = "kira-vault/tls-root/v1"

// tlsRootScalar is the root key's private scalar, 32 bytes, with its public point:
// HKDF of the master under tlsRootInfo and a counter, the first value that is a P-256
// scalar (all but about one in 2^32 are). The caller wipes the scalar.
func tlsRootScalar(master []byte) (d []byte, pub *ecdsa.PublicKey, err error) {
	if len(master) != MasterSize {
		return nil, nil, fmt.Errorf("a master of %d bytes, want %d", len(master), MasterSize)
	}
	for i := 0; i < 256; i++ {
		d, err = hkdf.Key(sha256.New, master, nil, fmt.Sprintf("%s/%d", tlsRootInfo, i), 32)
		if err != nil {
			return nil, nil, err
		}
		k, err := ecdh.P256().NewPrivateKey(d)
		if err != nil {
			Wipe(d)
			continue
		}
		p := k.PublicKey().Bytes() // 0x04 ‖ X ‖ Y
		return d, &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(p[1:33]), Y: new(big.Int).SetBytes(p[33:65])}, nil
	}
	return nil, nil, errors.New("no TLS root key follows from this master")
}

// TLSRootSoftKey is the root key outside a TPM, for the fake TPM of tests alone.
func TLSRootSoftKey(master []byte) (*ecdsa.PrivateKey, error) {
	d, pub, err := tlsRootScalar(master)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(d)}, nil
}

// TLSRootPublic is the root key's public area: an unrestricted ECDSA-SHA256 signing
// key on P-256, used by its (empty) authValue - serve signs a leaf with it at its
// start, with nobody there -, not fixed to a TPM (it follows from the master).
func TLSRootPublic(pub *ecdsa.PublicKey) *tpm2.TPMTPublic {
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: pub.X.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: pub.Y.FillBytes(make([]byte, 32))},
		}),
	}
}

// ImportTLSRoot imports the root key that follows from master under the storage
// primary, wrapped for the primary's public key as the master is (ImportMaster): not
// on the bus in the clear. The blob is master.json's.
func (t *TPM) ImportTLSRoot(master []byte) (*Blob, error) {
	d, pubKey, err := tlsRootScalar(master)
	if err != nil {
		return nil, err
	}
	defer Wipe(d)
	pub := TLSRootPublic(pubKey)
	sens := tpm2.Marshal(tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgECC,
		Sensitive:     tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgECC, &tpm2.TPM2BECCParameter{Buffer: d}),
	})
	defer Wipe(sens)
	return t.importObject(pub, sens, "the TLS root key")
}

// TLSRootPublicKey is the public key of the root key's blob.
func TLSRootPublicKey(b *Blob) (*ecdsa.PublicKey, error) {
	pub, err := b.public()
	if err != nil {
		return nil, err
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil || pub.Type != tpm2.TPMAlgECC || parms.CurveID != tpm2.TPMECCNistP256 {
		return nil, errors.New("the TLS root key is not a P-256 key")
	}
	pt, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	k := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pt.X.Buffer), Y: new(big.Int).SetBytes(pt.Y.Buffer)}
	if _, err := k.ECDH(); err != nil {
		return nil, fmt.Errorf("the TLS root key's point: %w", err)
	}
	return k, nil
}

// TLSRootSigner signs with the root key in the TPM: a crypto.Signer for
// x509.CreateCertificate (ECDSA over a SHA-256 digest, ASN.1). The key is loaded for
// each signature and flushed after it.
func (t *TPM) TLSRootSigner(b *Blob) (crypto.Signer, error) {
	pub, err := TLSRootPublicKey(b)
	if err != nil {
		return nil, err
	}
	return &tlsRootSigner{t: t, blob: b, pub: pub}, nil
}

type tlsRootSigner struct {
	t    *TPM
	blob *Blob
	pub  *ecdsa.PublicKey
}

func (s *tlsRootSigner) Public() crypto.PublicKey { return s.pub }

func (s *tlsRootSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, errors.New("the TLS root key signs SHA-256 digests alone")
	}
	var out []byte
	err := s.t.with(func(tp transport.TPM, srk *primary) error {
		key, flush, err := load(tp, srk, s.blob)
		if err != nil {
			return fmt.Errorf("the TLS root key: %w", err)
		}
		defer flush()
		rsp, err := tpm2.Sign{
			KeyHandle:  tpm2.AuthHandle{Handle: key.Handle, Name: key.Name, Auth: tpm2.PasswordAuth(nil)},
			Digest:     tpm2.TPM2BDigest{Buffer: digest},
			InScheme:   tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
		}.Execute(tp)
		if err != nil {
			return fmt.Errorf("signing with the TLS root key: %w", err)
		}
		sig, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return err
		}
		out, err = asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer)})
		return err
	})
	return out, err
}
