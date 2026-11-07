package bootstate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/tpm2-trust/kira/core/attest"
)

// Evidence is what the vault host's logs say of its boot, replayed against the live
// PCRs.
type Evidence struct {
	// SecureBoot is the firmware's log of PCR 7, replayed against the live PCR 7.
	SecureBoot attest.SecureBootFinding
	// Volume is the state directory's encrypted volume; nil with VolumeErr when it is
	// on none.
	Volume    *Volume
	VolumeErr error
	// PCR15Replays: systemd's measurement log replays to the live PCR 15; PCR15Err
	// says why not.
	PCR15Replays bool
	PCR15Err     error
	// Measured: the log holds the volume's cryptsetup: event. MeasuresVolumes: it holds
	// one of any volume - systemd-cryptsetup measures here; none, as with Debian's
	// initramfs-tools, and PCR 15 holds only what else was measured.
	Measured        bool
	MeasuresVolumes bool
}

// Paths are where Gather reads: the real ones, or a test's.
type Paths struct {
	FirmwareLog, MeasureLog string
	host                    host
}

// RealPaths are the host's.
var RealPaths = Paths{FirmwareLog: FirmwareLog, MeasureLog: MeasureLog, host: realHost}

// Gather is the evidence for the state directory stateDir and the live SHA-256
// values of PCR 7 and 15 (nil where not read).
func (p Paths) Gather(stateDir string, pcr7, pcr15 []byte) *Evidence {
	e := &Evidence{}
	raw, err := readBounded(p.FirmwareLog)
	switch {
	case err != nil:
		e.SecureBoot = attest.SecureBootFinding{State: attest.SecureBootNotEstablished, Detail: "the firmware's event log: " + err.Error()}
	default:
		events, err := ParseFirmwareLog(raw)
		if err != nil {
			e.SecureBoot = attest.SecureBootFinding{State: attest.SecureBootNotEstablished, Detail: err.Error()}
		} else {
			chain := Chain(events, 7)
			if len(chain) > attest.MaxPCR7Chain {
				chain = nil
			}
			e.SecureBoot = attest.EstablishSecureBoot(attest.AlgSHA256, pcr7, chain)
		}
	}

	e.Volume, e.VolumeErr = p.host.volumeOf(stateDir)
	raw, err = readBounded(p.MeasureLog)
	if err != nil {
		// No log: nothing of systemd's measured; PCR 15 replays if it is zero.
		raw = nil
	}
	records, err := ParseMeasureLog(raw)
	if err != nil {
		e.PCR15Err = err
		return e
	}
	chain, err := MeasureChain(records, 15)
	if err != nil {
		e.PCR15Err = err
		return e
	}
	switch {
	case len(pcr15) != sha256.Size:
		e.PCR15Err = fmt.Errorf("the live PCR 15 was not read")
	case !bytes.Equal(Replay(chain), pcr15):
		e.PCR15Err = fmt.Errorf("systemd's measurement log does not replay to PCR 15: something extended it without logging it")
	default:
		e.PCR15Replays = true
	}
	measured := measuredVolumes(records)
	e.MeasuresVolumes = len(measured) > 0
	if e.Volume != nil {
		e.Measured = slices.Contains(measured, cryptsetupEvent(e.Volume.Name, e.Volume.UUID))
	}
	return e
}

// Refusals are why an approval of pcrs must not be made on this evidence; none: it
// may. Notes are what is said beside an approval that may be made.
func (e *Evidence) Refusals(pcrs []uint8) (refusals, notes []string) {
	if slices.Contains(pcrs, 7) && e.SecureBoot.State != attest.SecureBootOn {
		refusals = append(refusals, "PCR 7: "+e.SecureBoot.String()+" - an approval of it would approve a boot whose signatures nobody checked")
	}
	if !slices.Contains(pcrs, 15) {
		return refusals, notes
	}
	switch {
	case e.Volume == nil:
		refusals = append(refusals, fmt.Sprintf("PCR 15: the state directory is %v: put it on an encrypted volume measured into PCR 15", e.VolumeErr))
	case !e.PCR15Replays:
		refusals = append(refusals, "PCR 15: "+e.PCR15Err.Error())
	case e.MeasuresVolumes && !e.Measured:
		refusals = append(refusals, fmt.Sprintf("PCR 15: systemd's measurement log has no measurement of the state directory's volume %s (%s): add tpm2-measure-pcr=yes to its crypttab line", e.Volume.Name, e.Volume.UUID))
	case !e.MeasuresVolumes:
		notes = append(notes, fmt.Sprintf("PCR 15: nothing measured the volumes into it (Debian's initramfs-tools measures nothing): it holds only what else was measured; serve checks at its start that the state directory is on %s", e.Volume.Name))
	}
	return refusals, notes
}

// CheckEncrypted is serve's start check: the state directory is on an encrypted
// volume, whatever measured it.
func CheckEncrypted(stateDir string) (*Volume, error) { return realHost.volumeOf(stateDir) }
