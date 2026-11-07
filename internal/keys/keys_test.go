package keys

import (
	"crypto/rand"
	"testing"
)

func newKey() []byte {
	k := make([]byte, KeySize)
	rand.Read(k)
	return k
}

func TestEncrypt(t *testing.T) {
	k := newKey()
	ct, err := Encrypt(k, []byte("wrapped R"), []byte("device"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Decrypt(k, ct, []byte("device")); err != nil || string(pt) != "wrapped R" {
		t.Fatalf("%q %v", pt, err)
	}
	if _, err := Decrypt(k, ct, []byte("another device")); err == nil {
		t.Fatal("opened under another AAD")
	}
	other := newKey()
	if _, err := Decrypt(other, ct, []byte("device")); err == nil {
		t.Fatal("opened under another key")
	}
}
