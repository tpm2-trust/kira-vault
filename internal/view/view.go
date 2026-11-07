// Package view is how the vault's records read for a person: a device, an audit line,
// a Secure Boot state, a one-time keyboard. The CLI prints them; control shows them.
package view

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/kira/core/attest"

	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
)

// YesNo is a flag in a table.
func YesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// PCRs is a selection, "none" when empty.
func PCRs(p []uint8) string {
	if len(p) == 0 {
		return "none"
	}
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(int(v))
	}
	return strings.Join(s, ",")
}

// DeviceState is "active", or what holds the device back.
func DeviceState(d *server.DeviceView) string {
	var s []string
	if d.Revoked {
		s = append(s, "revoked")
	}
	if d.Locked {
		s = append(s, "locked")
	}
	if len(s) == 0 {
		return "active"
	}
	return strings.Join(s, ",")
}

// When is a time, "never" when nil.
func When(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format(time.DateTime)
}

// Device is a device's record, one field per line.
func Device(w io.Writer, d *server.DeviceView) {
	fmt.Fprintf(w, "device:          %s\n", d.ID)
	fmt.Fprintf(w, "name:            %s\n", d.Name)
	fmt.Fprintf(w, "keyslot label:   %s\n", d.Label)
	fmt.Fprintf(w, "mode:            %s\n", d.Mode)
	fmt.Fprintf(w, "pepper:          %s\n", YesNo(d.Pepper))
	fmt.Fprintf(w, "state:           %s\n", DeviceState(d))
	fmt.Fprintf(w, "failures:        %d in a row\n", d.Failures)
	fmt.Fprintf(w, "min generation:  %d\n", d.MinGeneration)
	fmt.Fprintf(w, "machine PCRs:    %s (bank 0x%04x)\n", PCRs(d.Selection.Indices), d.Selection.Alg)
	fmt.Fprintf(w, "vault PCRs:      %s\n", PCRs(d.VaultPCRs))
	fmt.Fprintf(w, "enrolled:        %s\n", d.EnrolledAt.Local().Format(time.DateTime))
	fmt.Fprintf(w, "last release:    %s\n", When(d.LastRelease))
	fmt.Fprintf(w, "secure boot:     %s\n", Red(w, d.SecureBootRed, SecureBootLine(d.SecureBoot, d.SecureBootAt)))
}

// SecureBootLine is a state as a person reads it; every state but on carries the
// word WARNING, so that it stands out where there is no colour either.
func SecureBootLine(f attest.SecureBootFinding, at *time.Time) string {
	line := f.String()
	if f.Red() {
		line = "WARNING: " + line
	}
	if at != nil {
		line += " (established " + at.Local().Format(time.DateTime) + ")"
	}
	return line
}

// SecureBootWord is a state in a table's column.
func SecureBootWord(f attest.SecureBootFinding) string {
	switch f.State {
	case attest.SecureBootOn:
		return "on"
	case attest.SecureBootOff:
		return "OFF"
	case attest.SecureBootSetupMode:
		return "SETUP-MODE"
	}
	return "NOT-ESTABLISHED"
}

// Red colours text on a terminal, when on says so.
func Red(w io.Writer, on bool, text string) string {
	if !on {
		return text
	}
	if f, ok := w.(*os.File); ok {
		if _, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err == nil {
			return "\033[0;31m" + text + "\033[0m"
		}
	}
	return text
}

// Entry is an audit line for a person; a line that does not parse is printed as it
// is.
func Entry(line []byte) string {
	var e state.Entry
	if json.Unmarshal(line, &e) != nil {
		return string(line)
	}
	parts := []string{e.Time.Local().Format(time.DateTime), e.Event}
	if e.Result != "" {
		parts = append(parts, e.Result)
	}
	if e.Device != "" {
		dev := e.Device
		if e.Name != "" {
			dev += " (" + e.Name + ")"
		}
		parts = append(parts, dev)
	} else if e.Name != "" {
		parts = append(parts, e.Name)
	}
	if e.Request != "" {
		parts = append(parts, "request "+e.Request)
	}
	if e.Actor != "" {
		parts = append(parts, "by "+e.Actor)
	}
	if e.Remote != "" {
		parts = append(parts, "from "+e.Remote)
	}
	if e.Detail != "" {
		parts = append(parts, "- "+e.Detail)
	}
	if e.SecureBootRed {
		parts = append(parts, "- WARNING: "+e.SecureBoot)
	} else if e.SecureBoot != "" {
		parts = append(parts, "- "+e.SecureBoot)
	}
	return strings.Join(parts, "  ")
}

// Layout shows a one-time keyboard on a US keyboard, row by row: for each character of
// the pepper the person presses the key above the line it is on.
func Layout(w io.Writer, keyOrder, layout string) {
	if len(keyOrder) != len(layout) {
		fmt.Fprintln(w, "  (the vault sent a malformed layout)")
		return
	}
	for i, row := range attest.KeyboardUS {
		indent := strings.Repeat(" ", i*2)
		var keys, types strings.Builder
		for _, k := range []byte(row) {
			at := strings.IndexByte(keyOrder, k)
			if at < 0 {
				continue
			}
			fmt.Fprintf(&keys, " %c ", k)
			fmt.Fprintf(&types, " %c ", layout[at])
		}
		fmt.Fprintf(w, "  key   %s%s\n  types %s%s\n", indent, keys.String(), indent, types.String())
	}
}
