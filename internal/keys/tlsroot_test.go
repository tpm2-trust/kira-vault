package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// The TLS root key follows from the master alone: the same master makes the same key
// (a restore keeps the pin), another master another; it is a P-256 key that signs,
// and its public area names the same point.
func TestTLSRootFollowsFromTheMaster(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, MasterSize)
	a, err := TLSRootSoftKey(master)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := TLSRootSoftKey(master)
	if !a.Equal(b) {
		t.Fatal("one master, two root keys")
	}
	other, _ := TLSRootSoftKey(bytes.Repeat([]byte{0x43}, MasterSize))
	if a.Equal(other) {
		t.Fatal("two masters, one root key")
	}
	if _, err := TLSRootSoftKey(master[:16]); err == nil {
		t.Fatal("a short master makes a key")
	}
	digest := sha256.Sum256([]byte("a leaf"))
	sig, err := ecdsa.SignASN1(rand.Reader, a, digest[:])
	if err != nil || !ecdsa.VerifyASN1(&a.PublicKey, digest[:], sig) {
		t.Fatalf("the key does not sign: %v", err)
	}
	blob := &Blob{Public: tpm2.Marshal(tpm2.New2B(*TLSRootPublic(&a.PublicKey)))}
	pub, err := TLSRootPublicKey(blob)
	if err != nil || !pub.Equal(&a.PublicKey) {
		t.Fatalf("the public area's key: %v", err)
	}
	// It is not the master, nor the master's seed.
	seed, _ := masterSeed(master)
	if d := a.D.FillBytes(make([]byte, 32)); bytes.Equal(d, master) || bytes.Equal(d, seed) {
		t.Fatal("the root key is the master or its seed")
	}
}
