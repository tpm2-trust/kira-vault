package control

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/go-tui-slim/panel"
	"github.com/tpm2-trust/go-tui-slim/prompt"
	"github.com/tpm2-trust/go-tui-slim/tui"
	"github.com/tpm2-trust/kira/core/attest"
	"github.com/tpm2-trust/kira/core/vaultproto"

	"github.com/tpm2-trust/kira-vault/internal/bootstate"
	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
)

// testEnv is a host of a test's: a /proc of its own, no unit, no engine, serve's pid
// as the test says.
func testEnv(t *testing.T, pid int, cgroup string) *Env {
	t.Helper()
	proc := t.TempDir()
	if pid > 0 {
		os.MkdirAll(filepath.Join(proc, strconv.Itoa(pid)), 0o755)
		os.WriteFile(filepath.Join(proc, strconv.Itoa(pid), "cgroup"), []byte(cgroup), 0o644)
	}
	return &Env{
		Root: t.TempDir(), Proc: proc, EFIVars: t.TempDir(), UnitPaths: []string{filepath.Join(proc, "no-unit")}, QuadletPaths: nil,
		LookPath: func(string) (string, error) { return "", errors.New("none") },
		PeerPid: func(string) (int, error) {
			if pid < 0 {
				return 0, errors.New("nothing answers")
			}
			return pid, nil
		},
		Volume:     func(string) (*bootstate.Volume, error) { return &bootstate.Volume{Name: "root", UUID: "u"}, nil },
		Resolve:    func(string) ([]string, error) { return []string{"192.0.2.1"}, nil },
		LocalAddrs: func() ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.1")}, nil },
		Now:        time.Now,
	}
}

// How serve runs, from its cgroup and namespace: the unit, podman, docker, another
// pid namespace, neither, not at all.
func TestDeployment(t *testing.T) {
	for _, c := range []struct {
		pid          int
		cgroup, kind string
	}{
		{4242, "0::/system.slice/kira-vault.service\n", Unit},
		{4242, "0::/machine.slice/libpod-0123abcd.scope/container\n", Container},
		{4242, "0::/system.slice/docker-0123abcd.scope\n", Container},
		{0, "", Container},
		{4242, "0::/user.slice/user-1000.slice/session-2.scope\n", Elsewhere},
		{-1, "", Stopped},
	} {
		d := testEnv(t, c.pid, c.cgroup).deployment("/run/kira-vault/admin.sock")
		if d.Kind != c.kind {
			t.Errorf("%q: %s (%s), want %s", c.cgroup, d.Kind, d.Detail, c.kind)
		}
	}
	// control in serve's own container: its engine's mark.
	e := testEnv(t, 4242, "0::/\n")
	os.MkdirAll(filepath.Join(e.Root, "run"), 0o755)
	os.WriteFile(filepath.Join(e.Root, "run", ".containerenv"), nil, 0o644)
	if d := e.deployment("/run/kira-vault/admin.sock"); d.Kind != Container || d.Engine != "podman" {
		t.Errorf("in serve's container: %+v", d)
	}
}

// facts is a host with a vault as the test makes it.
func facts(t *testing.T, mutate func(*Facts)) *Facts {
	f := &Facts{Root: true, Dir: "/var/lib/kira-vault", DirExists: true, DirMode: 0o700,
		Config: &state.Config{URL: "https://vault.example:8443", Listen: ":8443", PCRs: []uint8{7, 15}, AdminSocket: "/run/kira-vault/admin.sock"},
		Master: &state.Master{}, Socket: "/run/kira-vault/admin.sock", SocketMode: 0o600,
		Deployment: Deployment{Kind: Unit}, Volume: &bootstate.Volume{Name: "root", UUID: "u"},
		DNS: &DNSCheck{Host: "vault.example", Addrs: []string{"192.0.2.1"}, Local: true}}
	f.SecureBoot.Known, f.SecureBoot.Enabled = true, true
	now := time.Now()
	f.Status = &server.StatusView{TPMPath: "/dev/tpmrm0", Devices: 2, Keys: &server.KeysStatus{Approved: &now, Counter: 3, ApprovalKeys: []string{"tpm"}, TPM: &keys.Info{Manufacturer: "IFX", MaxAuthFail: 32}}}
	if mutate != nil {
		mutate(f)
	}
	return f
}

func text(lines []Line) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(tui.StripSGR(l.String()) + "\n")
	}
	return b.String()
}

// The overview's lines: all green on a vault in place; each condition red or orange
// alone, with its risk.
func TestLines(t *testing.T) {
	if s := text(Lines(facts(t, nil), time.Now())); strings.Contains(s, "✗") || strings.Contains(s, "•") {
		t.Fatalf("a vault in place:\n%s", s)
	}
	for _, c := range []struct {
		name   string
		mutate func(*Facts)
		want   string
	}{
		{"not root", func(f *Facts) { f.Root = false }, "✗ not root"},
		{"a loose state dir", func(f *Facts) { f.DirMode = 0o755 }, "✗ /var/lib/kira-vault is -rwxr-xr-x, not 0700"},
		{"no encrypted volume", func(f *Facts) { f.Volume, f.VolumeErr = nil, bootstate.ErrNotEncrypted }, "✗ the state directory: not on an encrypted volume"},
		{"serve stopped", func(f *Facts) { f.Deployment.Kind = Stopped }, "✗ serve does not run"},
		{"serve elsewhere", func(f *Facts) { f.Deployment = Deployment{Kind: Elsewhere, Detail: "pid 7"} }, "• serve runs, neither under the unit nor in a container"},
		{"Secure Boot off", func(f *Facts) { f.SecureBoot.Enabled = false }, "✗ Secure Boot is off"},
		{"without PCR 15", func(f *Facts) { f.Config.PCRs = []uint8{7} }, "• PCRs 7, without 15"},
		{"approval due", func(f *Facts) { f.Status.Keys.ApprovalDue, f.Status.Keys.Moved = true, []uint8{15} }, "✗ due: PCR 15 moved"},
		{"lockout", func(f *Facts) { f.Status.Keys.TPM.InLockout = true }, "✗ /dev/tpmrm0, IFX: in dictionary-attack lockout"},
		{"DNS elsewhere", func(f *Facts) { f.DNS.Local = false }, "• vault.example is 192.0.2.1, not an address of this host"},
		{"DNS fails", func(f *Facts) { f.DNS.Err = errors.New("no such host") }, "✗ vault.example does not resolve"},
		{"TLS fails", func(f *Facts) { f.TLS = []TLSCheck{{Interface: "machines", Addr: ":8443", Err: errors.New("refused")}} }, "✗ :8443 does not answer as the vault"},
		{"operators everywhere", func(f *Facts) { f.Config.OperatorListen = ":8444" }, "• the operator interface listens on every address"},
		{"a loose socket", func(f *Facts) { f.SocketMode = 0o666 }, "✗ /run/kira-vault/admin.sock is -rw-rw-rw-, not 0600"},
		{"expired tokens", func(f *Facts) { f.Status.Tokens, f.Status.ExpiredTokens = 2, 1 }, "• 2 unused, 1 expired"},
		{"pending", func(f *Facts) { f.Status.PendingRequests = 1 }, "• 1 waiting for an operator"},
	} {
		if s := text(Lines(facts(t, c.mutate), time.Now())); !strings.Contains(s, c.want) {
			t.Errorf("%s: no %q in\n%s", c.name, c.want, s)
		}
	}
}

func step(t *testing.T, m []Section, key string) Step {
	t.Helper()
	for _, s := range m {
		for _, st := range s.Steps {
			if st.Key == key {
				return st
			}
		}
	}
	t.Fatalf("no step %s", key)
	return Step{}
}

// The steps' states: an empty host offers the vault's creation alone; a vault that
// does not serve offers running it; a serving one with an approval due marks it; its
// tokens, devices and requests are lines of their own.
func TestModel(t *testing.T) {
	empty := &Facts{Root: true, Dir: "/var/lib/kira-vault", Deployment: Deployment{Kind: Stopped}}
	m := Model(empty)
	if s := step(t, m, "init"); s.Done != "" || s.Blocked != "" || s.Run == nil {
		t.Errorf("create on an empty host: %+v", s.Step)
	}
	for _, k := range []string{"restore", "backup", "run", "enrol", "approve", "operator-listen"} {
		if s := step(t, m, k); s.Blocked == "" {
			t.Errorf("%s on an empty host is not blocked", k)
		}
	}
	stopped := facts(t, func(f *Facts) { f.Deployment.Kind = Stopped; f.Status = nil })
	m = Model(stopped)
	if s := step(t, m, "init"); s.Done == "" || !s.Check {
		t.Errorf("create on a vault: %+v", s.Step)
	}
	if s := step(t, m, "run"); s.Blocked != "" || s.Done != "" {
		t.Errorf("run it while stopped: %+v", s.Step)
	}
	if s := step(t, m, "enrol"); s.Blocked != "serve does not run" {
		t.Errorf("enrol while stopped: %+v", s.Step)
	}
	due := facts(t, func(f *Facts) {
		f.Status.Keys.ApprovalDue = true
		f.Tokens = []server.TokenView{{ID: "0123456789abcdef", Name: "web-1", Expired: true}}
		f.Devices = []server.DeviceView{{ID: "d1d1d1d1d1d1d1d1", Name: "db-03", Mode: vaultproto.ModeAuto, Locked: true}}
		f.Requests = []server.RequestView{{ID: "r1", Name: "db-04", State: "pending", SecureBoot: attest.SecureBootFinding{State: attest.SecureBootOn}}}
	})
	m = Model(due)
	if s := step(t, m, "approve"); s.Dirty == "" {
		t.Errorf("approve while due: %+v", s.Step)
	}
	if s := step(t, m, "token:0123456789abcdef"); s.Dirty == "" || s.Danger != panel.Destroys || !strings.Contains(s.Command, "token withdraw 0123456789abcdef") {
		t.Errorf("an expired token: %+v", s.Step)
	}
	if s := step(t, m, "device:d1d1d1d1d1d1d1d1"); !strings.Contains(s.Dirty, "locked") {
		t.Errorf("a locked device: %+v", s.Step)
	}
	if s := step(t, m, "request:r1"); s.Dirty == "" || !strings.Contains(s.Command, "request approve|deny r1") {
		t.Errorf("a pending request: %+v", s.Step)
	}
	if s := step(t, m, "menu:approvals"); s.Dirty == "" {
		t.Errorf("the overview's approvals line: %+v", s.Step)
	}
}

// recorder is the CLI as the actions see it: what they ran.
type recorder struct {
	mu   sync.Mutex
	runs []string
	out  string // what each run prints
}

func (r *recorder) cli(args []string, _ io.Reader, stdout, _ io.Writer) error {
	r.mu.Lock()
	r.runs = append(r.runs, strings.Join(args, " "))
	r.mu.Unlock()
	io.WriteString(stdout, r.out)
	return nil
}

// actor is a Control whose answers come from in, its CLI recorded.
func actor(t *testing.T, f *Facts, in string) (*Control, *recorder, *bytes.Buffer) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, in)
	w.Close()
	t.Cleanup(func() { r.Close() })
	rec := &recorder{}
	var out bytes.Buffer
	c := &Control{o: Options{Dir: t.TempDir(), CLI: rec.cli}, env: testEnv(t, -1, ""), in: r, out: &out, facts: f}
	c.p = prompt.New(r, &out)
	return c, rec, &out
}

// The actions run the commands they name, with what was answered: a token for a new
// machine and for one of a name enrolled (replacing it); a device revoked only on its
// name typed; a request approved; a token withdrawn only on "withdraw"; an operator
// added.
func TestActions(t *testing.T) {
	f := facts(t, func(f *Facts) {
		f.Devices = []server.DeviceView{{ID: "d1d1d1d1d1d1d1d1", Name: "db-03", Mode: vaultproto.ModeAuto}}
	})
	c, rec, _ := actor(t, f, "web-1\n1\nn\n")
	if err := c.enrol(); err != nil {
		t.Fatal(err)
	}
	if want := "token create --name web-1 --mode auto --socket /run/kira-vault/admin.sock"; len(rec.runs) != 1 || rec.runs[0] != want {
		t.Fatalf("enrol: %q", rec.runs)
	}
	c, rec, _ = actor(t, f, "db-03\n2\ny\nn\n")
	c.enrol()
	if len(rec.runs) != 1 || !strings.Contains(rec.runs[0], "--mode approve --replace d1d1d1d1d1d1d1d1") {
		t.Fatalf("enrol again: %q", rec.runs)
	}

	// revoke: the 3rd option of show, mode approve, revoke; a wrong name leaves it.
	c, rec, out := actor(t, f, "3\ndb-04\n")
	c.device(f.Devices[0])
	if len(rec.runs) != 0 || !strings.Contains(out.String(), "Left as it is") {
		t.Fatalf("revoke with the wrong name: %q\n%s", rec.runs, out)
	}
	c, rec, _ = actor(t, f, "3\ndb-03\n")
	c.device(f.Devices[0])
	if len(rec.runs) != 1 || rec.runs[0] != "device revoke d1d1d1d1d1d1d1d1 --socket /run/kira-vault/admin.sock" {
		t.Fatalf("revoke: %q", rec.runs)
	}

	c, rec, _ = actor(t, f, "1\n")
	c.request(server.RequestView{ID: "r1", Name: "db-04"})
	if len(rec.runs) != 1 || rec.runs[0] != "request approve r1 --socket /run/kira-vault/admin.sock" {
		t.Fatalf("approve a request: %q", rec.runs)
	}

	tok := server.TokenView{ID: "0123456789abcdef", Name: "web-1"}
	f.Tokens = []server.TokenView{tok}
	c, rec, _ = actor(t, f, "no\n")
	step(t, Model(f), "token:"+tok.ID).Run(c)
	if len(rec.runs) != 0 {
		t.Fatalf("a token withdrawn without its word: %q", rec.runs)
	}
	c, rec, _ = actor(t, f, "withdraw\n")
	step(t, Model(f), "token:"+tok.ID).Run(c)
	if len(rec.runs) != 1 || rec.runs[0] != "token withdraw 0123456789abcdef --socket /run/kira-vault/admin.sock" {
		t.Fatalf("withdraw: %q", rec.runs)
	}

	c, rec, _ = actor(t, f, "alice\n")
	step(t, Model(f), "operator-add").Run(c)
	if len(rec.runs) != 1 || rec.runs[0] != "operator add alice --socket /run/kira-vault/admin.sock" {
		t.Fatalf("operator add: %q", rec.runs)
	}
	// A view runs as it is; the approve step on this host, in-process.
	c, rec, _ = actor(t, f, "")
	step(t, Model(f), "approve").Run(c)
	if len(rec.runs) != 1 || !strings.HasPrefix(rec.runs[0], "approve --dir ") {
		t.Fatalf("approve: %q", rec.runs)
	}
}

// Without a terminal: everything printed, each step with its command, no colour.
func TestPrintout(t *testing.T) {
	r, w, _ := os.Pipe()
	w.Close()
	defer r.Close()
	var out bytes.Buffer
	dir := filepath.Join(t.TempDir(), "none")
	err := Run(Options{Dir: dir, CLI: (&recorder{}).cli, In: r, Out: &out, Env: testEnv(t, -1, ""), AllowUser: true})
	s := out.String()
	if err != nil || !strings.Contains(s, "none in "+dir+" yet") || !strings.Contains(s, "Create the vault") || !strings.Contains(s, "kira-vault init --dir") || strings.Contains(s, "\033[") {
		t.Fatalf("%v\n%s", err, s)
	}
}

func openPty(t *testing.T, cols, rows int) (ptm, pts *os.File) {
	t.Helper()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	pts, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.IoctlSetWinsize(int(ptm.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
	t.Cleanup(func() { ptm.Close(); pts.Close() })
	return ptm, pts
}

// The full screen on a pseudo-terminal: up with the header, the overview's facts, a
// step run below it (the firewall's advice) and the screen back; q leaves it as it was.
func TestFullScreenOnAPty(t *testing.T) {
	ptm, pts := openPty(t, 110, 34)
	before, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	var mu sync.Mutex
	var seen bytes.Buffer
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := ptm.Read(b)
			if err != nil {
				return
			}
			mu.Lock()
			seen.Write(b[:n])
			mu.Unlock()
		}
	}()
	shown := func() string { mu.Lock(); defer mu.Unlock(); return tui.StripSGR(seen.String()) }
	waitFor := func(want string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !strings.Contains(shown(), want); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("the screen never showed %q:\n%q", want, shown())
			}
		}
	}
	t.Setenv("TERM", "xterm")
	done := make(chan error, 1)
	go func() {
		done <- Run(Options{Dir: filepath.Join(t.TempDir(), "none"), CLI: (&recorder{}).cli, In: pts, Out: pts, Env: testEnv(t, -1, ""), AllowUser: true})
	}()
	waitFor("kira-vault control")
	waitFor("What the vault host and the vault have")
	ptm.Write([]byte("\033[B\r")) // Setup
	waitFor("Create the vault")
	ptm.Write([]byte("\033[B\033[B\033[B\033[B\033[B\r")) // the 6th step: the firewall's advice
	waitFor("Back to control")
	ptm.Write([]byte("\r"))
	ptm.Write([]byte("q"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("q did not leave:\n%q", shown())
	}
	after, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if after.Lflag != before.Lflag {
		t.Fatalf("the terminal is not as it was")
	}
}
