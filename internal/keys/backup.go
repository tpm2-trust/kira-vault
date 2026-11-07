package keys

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
)

// The backup is the master as a person writes it down: base32 of the master and two
// check bytes (the first two of its SHA-256), in groups of five joined by '-'. The
// check bytes catch a typo where it is typed back; they are the backup's, never kept
// by the vault. Everything is bytes, never a string: the caller wipes them.

var backupEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	backupCheck = 2
	groupSize   = 5
)

// backupRaw is the master and its check bytes.
const backupRaw = MasterSize + backupCheck

// BackupLen is the written backup's length.
var BackupLen = func() int {
	n := backupEncoding.EncodedLen(backupRaw)
	return n + (n-1)/groupSize
}()

// EncodeBackup is the backup of master to write down.
func EncodeBackup(master []byte) ([]byte, error) {
	if len(master) != MasterSize {
		return nil, errors.New("not a master key")
	}
	raw := make([]byte, 0, backupRaw)
	defer Wipe(raw[:cap(raw)])
	raw = append(raw, master...)
	sum := sha256.Sum256(master)
	raw = append(raw, sum[:backupCheck]...)
	Wipe(sum[:])
	enc := make([]byte, backupEncoding.EncodedLen(backupRaw))
	defer Wipe(enc)
	backupEncoding.Encode(enc, raw)
	out := make([]byte, 0, BackupLen)
	for i, c := range enc {
		if i > 0 && i%groupSize == 0 {
			out = append(out, '-')
		}
		out = append(out, c)
	}
	return out, nil
}

// ErrNotABackup is typing that is not a backup, or a backup with a typo.
var ErrNotABackup = errors.New("this is not a backup (or it has a typo): 11 groups of five letters and digits")

// ParseBackup is the master of a written backup; case, spaces and dashes do not
// matter.
func ParseBackup(typed []byte) ([]byte, error) {
	clean := make([]byte, 0, len(typed))
	defer Wipe(clean[:cap(clean)])
	for _, c := range typed {
		switch {
		case c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case c >= 'a' && c <= 'z':
			clean = append(clean, c-'a'+'A')
		default:
			clean = append(clean, c)
		}
	}
	if len(clean) != backupEncoding.EncodedLen(backupRaw) {
		return nil, ErrNotABackup
	}
	raw := make([]byte, backupRaw)
	defer Wipe(raw)
	if n, err := backupEncoding.Decode(raw, clean); err != nil || n != backupRaw {
		return nil, ErrNotABackup
	}
	sum := sha256.Sum256(raw[:MasterSize])
	defer Wipe(sum[:])
	if subtle.ConstantTimeCompare(sum[:backupCheck], raw[MasterSize:]) != 1 {
		return nil, ErrNotABackup
	}
	master := make([]byte, MasterSize)
	copy(master, raw)
	return master, nil
}
