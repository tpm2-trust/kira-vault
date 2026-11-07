package view

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tpm2-trust/kira/core/attest"
)

// The CLI shows each key above the character it types, row by row.
func TestLayout(t *testing.T) {
	l, err := attest.KeyboardLayoutOf(bytes.Repeat([]byte{4}, attest.KeyboardSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	Layout(&b, attest.KeyboardKeys, l.String())
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 2*len(attest.KeyboardUS) {
		t.Fatalf("%q", b.String())
	}
	for i, row := range attest.KeyboardUS {
		keys, types := strings.Fields(lines[2*i])[1:], strings.Fields(lines[2*i+1])[1:]
		if strings.Join(keys, "") != row || len(types) != len(row) {
			t.Fatalf("row %d: %q %q", i, lines[2*i], lines[2*i+1])
		}
		for j := range keys {
			if types[j][0] != l.Shows[strings.IndexByte(attest.KeyboardKeys, keys[j][0])] {
				t.Fatalf("key %s types %s", keys[j], types[j])
			}
		}
	}
	b.Reset()
	Layout(&b, attest.KeyboardKeys, "short")
	if !strings.Contains(b.String(), "malformed") {
		t.Fatal(b.String())
	}
}
