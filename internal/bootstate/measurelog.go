package bootstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// MeasureLog is systemd's log of what it measured into the TPM (systemd-pcrextend,
// systemd-cryptsetup's tpm2-measure-pcr=, and kira's close where kira is installed):
// JSON records, each after an RS (RFC 7464).
const MeasureLog = "/run/log/systemd/tpm2-measure.log"

// Record is one measurement of systemd's log in the SHA-256 bank.
type Record struct {
	PCR     int
	Digest  []byte // SHA-256; nil when the record has none
	Content string // what it says it measured, e.g. "cryptsetup:root:UUID"
}

// ParseMeasureLog reads systemd's log. A record that does not parse is an error: a
// log that cannot be read whole replays to nothing.
func ParseMeasureLog(raw []byte) ([]Record, error) {
	var out []Record
	for i, rec := range bytes.Split(raw, []byte{0x1e}) {
		rec = bytes.TrimSpace(rec)
		if len(rec) == 0 {
			continue
		}
		var r struct {
			PCR     *int `json:"pcr"`
			Digests []struct {
				HashAlg string `json:"hashAlg"`
				Digest  string `json:"digest"`
			} `json:"digests"`
			Content struct {
				String string `json:"string"`
			} `json:"content"`
		}
		if err := json.Unmarshal(rec, &r); err != nil || r.PCR == nil {
			return nil, fmt.Errorf("record %d of systemd's measurement log does not parse", i)
		}
		out = append(out, Record{PCR: *r.PCR, Content: r.Content.String})
		for _, d := range r.Digests {
			if d.HashAlg != "sha256" {
				continue
			}
			b, err := hex.DecodeString(d.Digest)
			if err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("record %d of systemd's measurement log: a SHA-256 digest that is none", i)
			}
			out[len(out)-1].Digest = b
		}
	}
	return out, nil
}

// MeasureChain is the SHA-256 digests the log extended pcr with, in its order; a
// record of pcr without a SHA-256 digest is an error (the bank cannot be replayed).
func MeasureChain(records []Record, pcr int) ([]byte, error) {
	var c []byte
	for _, r := range records {
		if r.PCR != pcr {
			continue
		}
		if r.Digest == nil {
			return nil, errors.New("systemd's measurement log has a record of PCR " + fmt.Sprint(pcr) + " without its SHA-256 digest")
		}
		c = append(c, r.Digest...)
	}
	return c, nil
}

// cryptsetupEvent is the content systemd-cryptsetup's tpm2-measure-pcr= logs for a
// volume: "cryptsetup:" its name ":" its LUKS UUID. The digest is the volume key's
// HMAC of it: replayable from the log, not computable without the key.
func cryptsetupEvent(name, uuid string) string { return "cryptsetup:" + name + ":" + uuid }

// measuredVolumes are the cryptsetup: events of PCR 15.
func measuredVolumes(records []Record) []string {
	var out []string
	for _, r := range records {
		if r.PCR == 15 && strings.HasPrefix(r.Content, "cryptsetup:") {
			out = append(out, r.Content)
		}
	}
	return out
}
