package keys

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Info is what the vault's TPM says of itself: its maker, and its dictionary-attack
// state, which the approval PIN counts against.
type Info struct {
	Manufacturer    string `json:"manufacturer"`     // the four letters of TPM_PT_MANUFACTURER
	LockoutCounter  uint32 `json:"lockout_counter"`  // wrong authorisations counted now
	MaxAuthFail     uint32 `json:"max_auth_fail"`    // the count at which it locks out
	LockoutInterval uint32 `json:"lockout_interval"` // seconds until one is forgiven
	InLockout       bool   `json:"in_lockout"`
}

// tpmAttrInLockout is TPMA_PERMANENT's inLockout.
const tpmAttrInLockout = 1 << 2

// Info reads it.
func (t *TPM) Info() (*Info, error) {
	var info *Info
	err := t.with(func(tp transport.TPM, _ *primary) error {
		props, err := properties(tp, tpm2.TPMPTManufacturer, 1)
		if err != nil {
			return err
		}
		da, err := properties(tp, tpm2.TPMPTLockoutCounter, 3)
		if err != nil {
			return err
		}
		perm, err := properties(tp, tpm2.TPMPTPermanent, 1)
		if err != nil {
			return err
		}
		m := props[tpm2.TPMPTManufacturer]
		info = &Info{
			Manufacturer:    strings.TrimRight(string([]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}), "\x00 "),
			LockoutCounter:  da[tpm2.TPMPTLockoutCounter],
			MaxAuthFail:     da[tpm2.TPMPTMaxAuthFail],
			LockoutInterval: da[tpm2.TPMPTLockoutInterval],
			InLockout:       perm[tpm2.TPMPTPermanent]&tpmAttrInLockout != 0,
		}
		return nil
	})
	return info, err
}

func properties(tp transport.TPM, first tpm2.TPMPT, n uint32) (map[tpm2.TPMPT]uint32, error) {
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties, Property: uint32(first), PropertyCount: n}.Execute(tp)
	if err != nil {
		return nil, fmt.Errorf("the TPM's properties: %w", err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return nil, err
	}
	out := map[tpm2.TPMPT]uint32{}
	for _, p := range props.TPMProperty {
		out[p.Property] = p.Value
	}
	return out, nil
}
