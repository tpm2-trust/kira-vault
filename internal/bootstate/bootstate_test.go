package bootstate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tpm2-trust/kira/core/attest"
)

// Real firmware's logs (OVMF, from kira's test machines): PCR 7's chain is kira's,
// digest for digest (the hashes of what kira's parser gives), and it says the state
// the machine was in.
func TestFirmwareLogsOfRealMachines(t *testing.T) {
	for _, c := range []struct {
		file, chain string
		events      int
		state       string
	}{
		{"arch-uki-eventlog.bin", "28ef6a434c815b9258a6d97b7fa64948f03b4945db21a6901385f55366e8bd8d", 7, attest.SecureBootOn},
		{"debian13-grub-eventlog.bin", "f48417a004199142ffd0ae08c1b9a63eb568ecd6006ba9e9893b3773a476c953", 7, attest.SecureBootSetupMode},
	} {
		raw, err := os.ReadFile(filepath.Join("testdata", c.file))
		if err != nil {
			t.Fatal(err)
		}
		events, err := ParseFirmwareLog(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		chain := Chain(events, 7)
		if sum := sha256.Sum256(chain); hex.EncodeToString(sum[:]) != c.chain || len(chain)/32 != c.events {
			t.Errorf("%s: %d events, chain %x", c.file, len(chain)/32, sum)
		}
		if got := attest.EstablishSecureBoot(attest.AlgSHA256, Replay(chain), chain); got.State != c.state {
			t.Errorf("%s: %+v, want %s", c.file, got, c.state)
		}
	}
	if _, err := ParseFirmwareLog([]byte("not a log")); err == nil {
		t.Error("a log that is none parsed")
	}
}

func digest(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }

func record(pcr int, content string) string {
	return fmt.Sprintf("\x1e{\"pcr\":%d,\"digests\":[{\"hashAlg\":\"sha1\",\"digest\":\"00\"},{\"hashAlg\":\"sha256\",\"digest\":%q}],\"content_type\":\"systemd\",\"content\":{\"string\":%q}}\n", pcr, digest(content), content)
}

// systemd's log: the records of a PCR in their order, a record without the bank or
// one that does not parse refused.
func TestMeasureLog(t *testing.T) {
	log := record(15, "kira-close") + record(11, "enter-initrd") + record(15, "cryptsetup:root:1b2a")
	recs, err := ParseMeasureLog([]byte(log))
	if err != nil || len(recs) != 3 {
		t.Fatalf("%v %v", recs, err)
	}
	chain, err := MeasureChain(recs, 15)
	if err != nil || len(chain) != 64 || hex.EncodeToString(chain[32:]) != digest("cryptsetup:root:1b2a") {
		t.Fatalf("PCR 15's chain: %x %v", chain, err)
	}
	if m := measuredVolumes(recs); len(m) != 1 || m[0] != "cryptsetup:root:1b2a" {
		t.Fatalf("the measured volumes: %v", m)
	}
	if _, err := ParseMeasureLog([]byte("\x1e{not json}\n")); err == nil {
		t.Error("a record that does not parse")
	}
	noBank, _ := ParseMeasureLog([]byte("\x1e{\"pcr\":15,\"digests\":[{\"hashAlg\":\"sha1\",\"digest\":\"00\"}]}\n"))
	if _, err := MeasureChain(noBank, 15); err == nil {
		t.Error("a PCR 15 record without SHA-256 replayed")
	}
}

// fakeHost is a /sys tree: devices by "major:minor", each a dm device or not, with
// its slaves; and a mountinfo.
type fakeHost struct {
	t    *testing.T
	root string
	devs map[string][2]uint32 // a path's device, the file's
	node map[string][2]uint32 // a device node's
}

func newFakeHost(t *testing.T) *fakeHost {
	return &fakeHost{t: t, root: t.TempDir(), devs: map[string][2]uint32{}, node: map[string][2]uint32{}}
}

// block makes a block device NAME at MAJ:MIN; uuid "" is not a dm device.
func (f *fakeHost) block(name string, major, minor uint32, dmName, dmUUID string, slaves ...string) {
	dir := filepath.Join(f.root, "sys", "class", "block", name)
	os.MkdirAll(filepath.Join(dir, "slaves"), 0o755)
	if dmUUID != "" {
		os.MkdirAll(filepath.Join(dir, "dm"), 0o755)
		os.WriteFile(filepath.Join(dir, "dm", "uuid"), []byte(dmUUID+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "dm", "name"), []byte(dmName+"\n"), 0o644)
	}
	for _, s := range slaves {
		os.MkdirAll(filepath.Join(dir, "slaves", s), 0o755)
	}
	os.MkdirAll(filepath.Join(f.root, "sys", "dev", "block"), 0o755)
	os.Symlink(dir, filepath.Join(f.root, "sys", "dev", "block", fmt.Sprintf("%d:%d", major, minor)))
}

func (f *fakeHost) host(mountinfo string) host {
	mi := filepath.Join(f.root, "mountinfo")
	os.WriteFile(mi, []byte(mountinfo), 0o644)
	return host{sys: filepath.Join(f.root, "sys"), mountinfo: mi, dev: func(path string, node bool) (uint32, uint32, error) {
		m := f.devs
		if node {
			m = f.node
		}
		d, ok := m[path]
		if !ok {
			return 0, 0, os.ErrNotExist
		}
		return d[0], d[1], nil
	}}
}

const cryptUUID = "CRYPT-LUKS2-1b2a3c4d5e6f40718293a4b5c6d7e8f9-root"

// The state directory's volume: on dm-crypt directly, through LVM, on btrfs (whose
// files have no block device of their own: the mount's source is taken), on none.
func TestVolumeOf(t *testing.T) {
	f := newFakeHost(t)
	f.block("dm-0", 254, 0, "root", cryptUUID, "vda2")
	f.block("vda2", 252, 2, "", "")
	f.block("dm-1", 254, 1, "vg-vault", "LVM-abc", "dm-0")
	f.block("vda1", 252, 1, "", "")
	f.devs["/var/lib/kira-vault"] = [2]uint32{254, 0}
	f.devs["/srv/vault"] = [2]uint32{254, 1}
	f.devs["/boot/vault"] = [2]uint32{252, 1}
	f.devs["/btrfs/vault"] = [2]uint32{0, 42}
	f.node["/dev/mapper/root"] = [2]uint32{254, 0}
	h := f.host("36 1 0:42 / /btrfs rw - btrfs /dev/mapper/root rw\n37 1 0:43 / /btrfs/other rw - btrfs /dev/other rw\n")
	want := Volume{Name: "root", UUID: "1b2a3c4d-5e6f-4071-8293-a4b5c6d7e8f9"}
	for _, path := range []string{"/var/lib/kira-vault", "/srv/vault", "/btrfs/vault"} {
		v, err := h.volumeOf(path)
		if err != nil || *v != want {
			t.Errorf("%s: %+v %v", path, v, err)
		}
	}
	if _, err := h.volumeOf("/boot/vault"); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("a plain partition: %v", err)
	}
	if got := unescapeMount(`/mnt/with\040space`); got != "/mnt/with space" {
		t.Errorf("unescape: %q", got)
	}
}

// The rules of an approval, each condition alone.
func TestRefusals(t *testing.T) {
	on := attest.SecureBootFinding{State: attest.SecureBootOn}
	vol := &Volume{Name: "root", UUID: "u"}
	good := Evidence{SecureBoot: on, Volume: vol, PCR15Replays: true, Measured: true, MeasuresVolumes: true}
	for _, c := range []struct {
		name   string
		change func(*Evidence)
		pcrs   []uint8
		refuse string
		note   string
	}{
		{"all in place", func(*Evidence) {}, []uint8{7, 15}, "", ""},
		{"Secure Boot off", func(e *Evidence) { e.SecureBoot = attest.SecureBootFinding{State: attest.SecureBootOff} }, []uint8{7, 15}, "PCR 7", ""},
		{"Secure Boot off, 7 not selected", func(e *Evidence) { e.SecureBoot = attest.SecureBootFinding{State: attest.SecureBootOff} }, []uint8{15}, "", ""},
		{"no encrypted volume", func(e *Evidence) { e.Volume, e.VolumeErr = nil, ErrNotEncrypted }, []uint8{7, 15}, "encrypted volume", ""},
		{"the log does not replay", func(e *Evidence) { e.PCR15Replays, e.PCR15Err = false, errors.New("does not replay") }, []uint8{15}, "does not replay", ""},
		{"the volume not measured", func(e *Evidence) { e.Measured = false }, []uint8{15}, "tpm2-measure-pcr=yes", ""},
		{"nothing measures volumes", func(e *Evidence) { e.Measured, e.MeasuresVolumes = false, false }, []uint8{15}, "", "initramfs-tools"},
		{"15 not selected", func(e *Evidence) { e.Volume = nil }, []uint8{7}, "", ""},
	} {
		e := good
		c.change(&e)
		refusals, notes := e.Refusals(c.pcrs)
		if got := strings.Join(refusals, "|"); (c.refuse == "") != (got == "") || !strings.Contains(got, c.refuse) {
			t.Errorf("%s: refusals %q, want %q", c.name, got, c.refuse)
		}
		if got := strings.Join(notes, "|"); (c.note == "") != (got == "") || !strings.Contains(got, c.note) {
			t.Errorf("%s: notes %q, want %q", c.name, got, c.note)
		}
	}
}

// Gather from files: the logs replayed against the live values given.
func TestGather(t *testing.T) {
	f := newFakeHost(t)
	f.block("dm-0", 254, 0, "root", cryptUUID)
	f.devs["/var/lib/kira-vault"] = [2]uint32{254, 0}
	measure := filepath.Join(f.root, "measure.log")
	os.WriteFile(measure, []byte(record(15, "kira-close")+record(15, "cryptsetup:root:1b2a3c4d-5e6f-4071-8293-a4b5c6d7e8f9")), 0o644)
	recs, _ := ParseMeasureLog([]byte(record(15, "kira-close") + record(15, "cryptsetup:root:1b2a3c4d-5e6f-4071-8293-a4b5c6d7e8f9")))
	chain, _ := MeasureChain(recs, 15)
	pcr15 := Replay(chain)
	raw, _ := os.ReadFile("testdata/arch-uki-eventlog.bin")
	events, _ := ParseFirmwareLog(raw)
	pcr7 := Replay(Chain(events, 7))
	p := Paths{FirmwareLog: "testdata/arch-uki-eventlog.bin", MeasureLog: measure, host: f.host("")}
	e := p.Gather("/var/lib/kira-vault", pcr7, pcr15)
	if refusals, notes := e.Refusals([]uint8{7, 15}); len(refusals) != 0 || len(notes) != 0 {
		t.Fatalf("%+v: %v %v", e, refusals, notes)
	}
	moved := sha256.Sum256(append(pcr15, 1))
	if refusals, _ := p.Gather("/var/lib/kira-vault", pcr7, moved[:]).Refusals([]uint8{15}); len(refusals) != 1 || !strings.Contains(refusals[0], "does not replay") {
		t.Fatalf("an unlogged extend: %v", refusals)
	}
	if e := p.Gather("/var/lib/kira-vault", make([]byte, 32), pcr15); e.SecureBoot.State == attest.SecureBootOn {
		t.Fatalf("a PCR 7 the log does not replay to: %+v", e.SecureBoot)
	}
}
