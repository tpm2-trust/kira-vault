// Package bootstate is what an approval of the vault's boot state rests on, besides
// the PIN: the vault host's Secure Boot, read from the firmware's event log replayed
// against the live PCR 7, and the state directory's encrypted volume, read from
// systemd's measurement log replayed against the live PCR 15. It reads files alone and
// never the TPM: the caller gives the live values.
package bootstate

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	evlog "github.com/google/go-attestation/attest"
)

// FirmwareLog is the firmware's event log of the TPM.
const FirmwareLog = "/sys/kernel/security/tpm0/binary_bios_measurements"

// maxLog bounds what is read of a log: a machine's are a few dozen KiB.
const maxLog = 4 << 20

// Event is one event of the firmware's log, in the SHA-256 bank.
type Event struct {
	PCR    uint32
	Type   uint32
	Digest []byte // SHA-256
}

// evNoAction extends nothing.
const evNoAction = 0x00000003

// readBounded reads at most maxLog bytes of path; a longer file is an error.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxLog+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxLog {
		return nil, fmt.Errorf("%s is longer than %d bytes", path, maxLog)
	}
	return b, nil
}

// ParseFirmwareLog reads the firmware's event log with go-attestation, as kira does:
// one parser for both, fuzzed, with its workarounds for known firmware. Each event's
// PCR, type and SHA-256 digest; a log without the SHA-256 bank is an error.
func ParseFirmwareLog(raw []byte) ([]Event, error) {
	log, err := evlog.ParseEventLog(raw)
	if err != nil {
		return nil, fmt.Errorf("the firmware's event log: %w", err)
	}
	var out []Event
	for _, e := range log.Events(evlog.HashSHA256) {
		if len(e.Digest) != sha256.Size {
			return nil, errors.New("the firmware's event log has no SHA-256 bank")
		}
		out = append(out, Event{PCR: uint32(e.Index), Type: uint32(e.Type), Digest: e.Digest})
	}
	if len(out) == 0 {
		return nil, errors.New("the firmware's event log has no events in the SHA-256 bank")
	}
	return out, nil
}

// Chain is the SHA-256 digests of what went into pcr, in the log's order: what
// replays to the register. EV_NO_ACTION extends nothing and is left out.
func Chain(events []Event, pcr uint32) []byte {
	var c []byte
	for _, e := range events {
		if e.PCR == pcr && e.Type != evNoAction {
			c = append(c, e.Digest...)
		}
	}
	return c
}

// Replay is a SHA-256 PCR's value after chain's digests, from zero.
func Replay(chain []byte) []byte {
	v := make([]byte, sha256.Size)
	for off := 0; off+sha256.Size <= len(chain); off += sha256.Size {
		h := sha256.New()
		h.Write(v)
		h.Write(chain[off : off+sha256.Size])
		v = h.Sum(nil)
	}
	return v
}
