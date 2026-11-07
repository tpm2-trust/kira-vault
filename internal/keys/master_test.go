package keys

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// The policies' digests, pinned: the master's policy is in its public area, imported
// once; a change here is a change of every vault's master (made again from the backup)
// and of every approval (approved again). It needs a "what breaks" and the owner's
// word (kira's AGENTS.md, as for its derivations).
func TestPolicyDigestsKnownAnswer(t *testing.T) {
	keyA := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{0xA1}, 32)...)
	keyB := append([]byte{0x00, 0x0B}, bytes.Repeat([]byte{0xB2}, 32)...)
	one, _ := MasterPolicy([][]byte{keyA})
	two, _ := MasterPolicy([][]byte{keyA, keyB})
	counter, _ := CounterPolicy([][]byte{keyA})
	counterName, _ := CounterName([][]byte{keyA})
	approved, err := ApprovedPolicy(&Approved{PCRs: []uint8{7, 15}, Values: [][]byte{bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{15}, 32)}, Counter: 3}, counterName)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		got  []byte
		want string
	}{
		{"master, one key", one, "3db5091826eab523752fe442f459965a35c2daadf4fe9683939db9cf21e8f464"},
		{"master, two keys", two, "c8bf5acbc693ba05f7e18986f87d8fd29678395b6925d35e84c74a2819dc627a"},
		{"counter policy", counter, "8b868289e01a0adcf6159cdff06c44416845acdce07cf9ea1b0ff8dac4d5204b"},
		{"counter name", counterName, "000b49202403e46f0d7376bdbded7d85ce8a299f7e1f3aec7e7c919cd9572a5f40d6"},
		{"approved policy", approved, "0cdf55397a945f34d76177e6cbcd4829bb1544e4bd1bb9163802aa7862923927"},
		{"approval digest", ApprovalDigest(approved), "855486de70d92247acc6888add23e39eced67a676e8f39987d030cf195b538a7"},
	} {
		if hex.EncodeToString(c.got) != c.want {
			t.Errorf("%s = %x, want %s", c.name, c.got, c.want)
		}
	}
}

// What an approval is checked against before anything is computed of it.
func TestApprovedChecks(t *testing.T) {
	v := bytes.Repeat([]byte{1}, 32)
	for _, a := range []Approved{
		{},
		{PCRs: []uint8{7}, Values: nil},
		{PCRs: []uint8{15, 7}, Values: [][]byte{v, v}},
		{PCRs: []uint8{7, 7}, Values: [][]byte{v, v}},
		{PCRs: []uint8{24}, Values: [][]byte{v}},
		{PCRs: []uint8{7}, Values: [][]byte{v[:20]}},
	} {
		if _, err := ApprovedPolicy(&a, nil); err == nil {
			t.Errorf("%+v taken", a)
		}
	}
	if _, err := MasterPolicy(nil); err == nil {
		t.Error("a master without a key")
	}
	if _, err := MasterPolicy(make([][]byte, MaxApprovalKeys+1)); err == nil {
		t.Error("more keys than PolicyOR takes")
	}
}

// The backup: written, typed back in any case and with any dashes; a typo is caught;
// it rebuilds the master's public area alone.
func TestBackup(t *testing.T) {
	master := bytes.Repeat([]byte{0x5C}, MasterSize)
	b, err := EncodeBackup(master)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != BackupLen || bytes.Count(b, []byte("-")) != 10 {
		t.Fatalf("the backup %q: %d bytes", b, len(b))
	}
	typed := bytes.ToLower(bytes.ReplaceAll(b, []byte("-"), []byte(" ")))
	back, err := ParseBackup(typed)
	if err != nil || !bytes.Equal(back, master) {
		t.Fatalf("typed back: %x %v", back, err)
	}
	for i := 0; i < len(b); i++ {
		if b[i] == '-' {
			continue
		}
		typo := bytes.Clone(b)
		typo[i] = map[bool]byte{true: 'B', false: 'A'}[typo[i] == 'A']
		if _, err := ParseBackup(typo); !errors.Is(err, ErrNotABackup) {
			t.Fatalf("a typo at %d taken: %v", i, err)
		}
	}
	if _, err := ParseBackup(b[:len(b)-1]); !errors.Is(err, ErrNotABackup) {
		t.Fatal("a short backup taken")
	}
	pub, _ := MasterPublic(master, []byte("policy"))
	pub2, _ := MasterPublic(back, []byte("policy"))
	if !bytes.Equal(tpm2.Marshal(pub), tpm2.Marshal(pub2)) {
		t.Fatal("the backup does not rebuild the public area")
	}
}
