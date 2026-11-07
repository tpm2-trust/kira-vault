package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tpm2-trust/kira/core/attest"

	"github.com/tpm2-trust/kira-vault/internal/approval"
	"github.com/tpm2-trust/kira-vault/internal/bootstate"
	"github.com/tpm2-trust/kira-vault/internal/vaulttest"
)

// locks counts the process locks the commands asked for.
var locks int

// The in-process tests run on a software TPM and temporary sockets, and must not lock
// the test process: both checks are the tests' own here, and tested below as they are.
func TestMain(m *testing.M) {
	lockProcess = func() error { locks++; return nil }
	reachable = func(string, string) error { return nil }
	controlAllowUser = true
	// The vault host of the tests: its logs say all is well (bootstate's tests say
	// what they say otherwise), its state directory on an encrypted volume.
	gatherEvidence = func(string, []byte, []byte) *bootstate.Evidence {
		return &bootstate.Evidence{SecureBoot: attest.SecureBootFinding{State: attest.SecureBootOn}, Volume: &bootstate.Volume{Name: "root", UUID: "u"}, PCR15Replays: true, Measured: true, MeasuresVolumes: true}
	}
	checkEncrypted = func(string) (*bootstate.Volume, error) { return &bootstate.Volume{Name: "root", UUID: "u"}, nil }
	// A TPM path "fake:NAME" is a software TPM, one per name: init, serve and approve
	// of a test's vault share it. Any other path is a real one (swtpm, -tags integration).
	real := newTPM
	newTPM = func(path string) approval.TPM {
		if name, ok := strings.CutPrefix(path, "fake:"); ok {
			fakesMu.Lock()
			defer fakesMu.Unlock()
			if fakes[name] == nil {
				fakes[name] = vaulttest.NewTPM()
			}
			return fakes[name]
		}
		return real(path)
	}
	os.Exit(m.Run())
}

var (
	fakesMu sync.Mutex
	fakes   = map[string]*vaulttest.TPM{}
)

// fakeTPM is the software TPM of a "fake:" path.
func fakeTPM(path string) *vaulttest.TPM { return newTPM(path).(*vaulttest.TPM) }

// The commands that hold a secret lock the process first, and stop before anything if
// it cannot be; the others do not lock.
func TestSecretCommandsLockFirst(t *testing.T) {
	for _, cmd := range []string{"init", "serve", "approve", "backup", "token", "request", "requests", "operator", "control"} {
		if !holdsSecrets(cmd) {
			t.Errorf("%s does not lock", cmd)
		}
	}
	for _, cmd := range []string{"help", "devices", "device", "operators", "audit", "tls", "config", "approvals"} {
		if holdsSecrets(cmd) {
			t.Errorf("%s locks, and holds no secret", cmd)
		}
	}
	old := lockProcess
	t.Cleanup(func() { lockProcess = old })
	lockProcess = func() error { return errors.New("no CAP_IPC_LOCK") }
	dir := filepath.Join(t.TempDir(), "vault")
	_, err := cli(t, "", "init", "--dir", dir)
	if err == nil || !strings.Contains(err.Error(), "not locked in memory") || !strings.Contains(err.Error(), "LimitMEMLOCK=infinity") {
		t.Fatalf("init without a lock: %v", err)
	}
	if _, serr := os.Stat(dir); !os.IsNotExist(serr) {
		t.Fatal("init wrote before it refused")
	}
	if _, err := cli(t, "", "help"); err != nil {
		t.Fatalf("help needs no lock: %v", err)
	}
}

// init takes the TPM and the admin socket the unit and the container reach, and no
// other: a release build no software TPM's socket.
func TestReachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "swtpm.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, c := range []struct {
		tpm, admin string
		ok         bool
	}{
		{"/dev/tpmrm0", "/run/kira-vault/admin.sock", true},
		{"/dev/tpm0", "/run/kira-vault/other.sock", true},
		{"/dev/tpmrm0", "/tmp/admin.sock", false},
		{"/dev/tpmrm0", "/run/kira-vault/sub/admin.sock", false},
		{"/dev/sda", "/run/kira-vault/admin.sock", false},
		{sock, "/run/kira-vault/admin.sock", socketTPM},
		{filepath.Join(t.TempDir(), "none"), "/run/kira-vault/admin.sock", false},
	} {
		if err := checkReachable(c.tpm, c.admin); (err == nil) != c.ok {
			t.Errorf("checkReachable(%s, %s) = %v, want ok %v", c.tpm, c.admin, err, c.ok)
		}
	}
}
