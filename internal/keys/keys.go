// Package keys holds the vault's keys: the master in the vault's TPM, the approval
// key and the counter (master.go, vaulttpm.go), the backup (backup.go), and the
// AES-256-GCM that a machine's key K_dev encrypts its record with.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the size of K_dev.
const KeySize = 32

// Wipe overwrites a secret.
func Wipe(b []byte) { clear(b) }

// Encrypt is AES-256-GCM: nonce ‖ ciphertext ‖ tag.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt opens what Encrypt made.
func Decrypt(key, sealed, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	n := g.NonceSize()
	return g.Open(nil, sealed[:n], sealed[n:], aad)
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key of %d bytes, want %d", len(key), KeySize)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
