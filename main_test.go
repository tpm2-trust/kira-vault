package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/tpm2-trust/kira-vault/internal/view"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/tpm2-trust/kira/core/attest"
	"github.com/tpm2-trust/kira/core/vaultproto"

	"github.com/tpm2-trust/kira-vault/internal/approval"
	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
	"github.com/tpm2-trust/kira-vault/internal/vaulttest"
)

// vault is a state directory made by init, and serve running on it.
type vault struct {
	t      *testing.T
	dir    string
	sock   string
	url    string
	pin    string
	root   []byte // the vault's root, as 'tls root' prints it
	backup string // the master's backup, as init shows it
	tpm    string
	stop   func()
}

// testPIN is the approval PIN of the tests' vaults.
const testPIN = "246810"

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// cli runs the command line and returns its output.
func cli(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out, &errOut)
	return out.String() + errOut.String(), err
}

var (
	pinRE      = regexp.MustCompile(`pin:\s+(sha256:[0-9a-f]{64})`)
	backupRE   = regexp.MustCompile(`\n    ([A-Z2-7]{5}(?:-[A-Z2-7]{5}){10})\n`)
	tokenRE    = regexp.MustCompile(`token:\s+(\S+)`)
	operatorRE = regexp.MustCompile(`token \(shown this once\):\n\n  (\S+)\n`)
)

// initVault runs init with these extra arguments, on a software TPM of its own unless
// they name one; the approval PIN is testPIN.
func initVault(t *testing.T, extra ...string) *vault {
	t.Helper()
	dir := t.TempDir()
	addr := freePort(t)
	v := &vault{t: t, dir: filepath.Join(dir, "state"), sock: filepath.Join(dir, "admin.sock"), url: "https://" + addr, tpm: "fake:" + dir}
	args := []string{"init", "--dir", v.dir, "--listen", addr, "--url", v.url, "--admin-socket", v.sock}
	for i, a := range extra {
		if a == "--tpm" && i+1 < len(extra) {
			v.tpm = extra[i+1]
		}
	}
	if !slices.Contains(extra, "--tpm") {
		args = append(args, "--tpm", v.tpm)
	}
	out, err := cli(t, testPIN+"\n"+testPIN+"\n", append(args, extra...)...)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	m := pinRE.FindStringSubmatch(out)
	b := backupRE.FindStringSubmatch(out)
	if m == nil || b == nil {
		t.Fatalf("init output:\n%s", out)
	}
	v.pin, v.backup = m[1], b[1]
	root, err := cli(t, "", "tls", "root", "--dir", v.dir)
	if err != nil || !strings.HasPrefix(root, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("tls root: %v\n%s", err, root)
	}
	v.root = []byte(root)
	return v
}

// start runs serve until stop.
func (v *vault) start() {
	v.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- serve(ctx, state.Dir{Path: v.dir}, io.Discard, ready) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		v.t.Fatalf("serve: %v", err)
	}
	v.stop = func() {
		cancel()
		if err := <-done; err != nil {
			v.t.Errorf("serve: %v", err)
		}
		v.stop = nil
	}
	v.t.Cleanup(func() {
		if v.stop != nil {
			v.stop()
		}
	})
}

// operator adds an operator with the CLI and returns its client of the
// operator interface.
func (v *vault) operator(name string) *vaulttest.Operator {
	v.t.Helper()
	out, err := cli(v.t, "", "operator", "add", name, "--socket", v.sock)
	if err != nil {
		v.t.Fatalf("operator add: %v\n%s", err, out)
	}
	m := operatorRE.FindStringSubmatch(out)
	if m == nil {
		v.t.Fatalf("operator add output:\n%s", out)
	}
	cfg, _ := state.Dir{Path: v.dir}.Config()
	u := server.OperatorURL(cfg)
	if !strings.Contains(out, "curl --cacert vault-ca.pem -H 'Authorization: Bearer "+m[1]+"' "+u+"/v1/requests") {
		v.t.Fatalf("operator add output:\n%s", out)
	}
	return vaulttest.NewOperator(u, v.root, v.pin, m[1])
}

// approve approves the machine's pending request over the operator
// interface and returns the release.
func approve(t *testing.T, v *vault, o *vaulttest.Operator, m *vaulttest.Machine, body string) *vaultproto.ReleaseResponse {
	t.Helper()
	req, res, err := m.Release(v.client())
	if err != nil || res.Status != vaultproto.StatusPending {
		t.Fatalf("approve mode: %v %+v", err, res)
	}
	if code, b, err := o.Do("POST", "/v1/requests/"+req.RequestID+"/approve", body); err != nil || code != 200 {
		t.Fatalf("approve: %d %s %v", code, b, err)
	}
	if res, err = v.client().Send(req); err != nil {
		t.Fatal(err)
	}
	return res
}

func (v *vault) client() *vaulttest.Client { return vaulttest.NewClient(v.url, v.root, v.pin) }

// enrol creates a token with the CLI and enrols a machine with it.
func (v *vault) enrol(name string) *vaulttest.Machine { return v.enrolWith(name, false) }

// enrolWith enrols a machine whose keyslot takes an operator's pepper or
// not.
func (v *vault) enrolWith(name string, pepper bool) *vaulttest.Machine {
	v.t.Helper()
	out, err := cli(v.t, "", "token", "create", "--name", name, "--socket", v.sock)
	if err != nil {
		v.t.Fatalf("token create: %v\n%s", err, out)
	}
	tok := tokenRE.FindStringSubmatch(out)
	if tok == nil || !strings.Contains(out, "kira vault enrol --url "+v.url+" --pin "+v.pin+" --token "+tok[1]) {
		v.t.Fatalf("token create output:\n%s", out)
	}
	m, err := vaulttest.NewMachine(name)
	if err != nil {
		v.t.Fatal(err)
	}
	m.Pepper = pepper
	if _, err := m.Enrol(v.client(), tok[1]); err != nil {
		v.t.Fatalf("enrol: %v", err)
	}
	return m
}

func (v *vault) release(m *vaulttest.Machine) *vaultproto.ReleaseResponse {
	v.t.Helper()
	_, res, err := m.Release(v.client())
	if err != nil {
		v.t.Fatalf("release: %v", err)
	}
	return res
}

func wantReleased(t *testing.T, m *vaulttest.Machine, res *vaultproto.ReleaseResponse) {
	t.Helper()
	if res.Status != vaultproto.StatusReleased {
		t.Fatalf("got %s (%s), want released", res.Status, res.Reason)
	}
	if r, err := m.Open(res.Remote); err != nil || !bytes.Equal(r, m.R) {
		t.Fatalf("the released part does not open: %v", err)
	}
}

// init, serve, the admin commands and an approval of a moved boot state, end to end,
// on a software TPM whose PCRs the test moves.
func TestCommands(t *testing.T) {
	v := initVault(t)
	opAddr := freePort(t)
	if _, err := cli(t, "", "init", "--dir", v.dir, "--url", v.url); err == nil || !strings.Contains(err.Error(), "holds a vault already") {
		t.Fatalf("init twice: %v", err)
	}

	v.start()
	m := v.enrol("db-03")
	wantReleased(t, m, v.release(m))

	// approve works beside a running serve: nothing to approve now.
	if out, err := cli(t, "", "approve", "--dir", v.dir); err != nil || !strings.Contains(out, "approved already") {
		t.Fatalf("approve while serving: %v\n%s", err, out)
	}

	out, err := cli(t, "", "devices", "--dir", v.dir)
	if err != nil || !strings.Contains(out, "db-03") || !strings.Contains(out, "active") {
		t.Fatalf("devices: %v\n%s", err, out)
	}
	secureBootInTheCLI(t, v, m)
	if out, err = cli(t, "", "device", "revoke", "db-03", "--socket", v.sock); err != nil || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if res := v.release(m); res.Status != vaultproto.StatusDenied {
		t.Fatalf("a revoked device: %s", res.Status)
	}
	// A revoke is final: the way back is a new enrolment.
	if _, err := cli(t, "", "device", "unrevoke", "db-03", "--socket", v.sock); err == nil {
		t.Fatal("unrevoke ran")
	}
	out, err = cli(t, "", "token", "create", "--name", "db-03", "--replace", "db-03", "--socket", v.sock)
	tok := tokenRE.FindStringSubmatch(out)
	if err != nil || tok == nil {
		t.Fatalf("token --replace: %v\n%s", err, out)
	}
	if _, err := m.Enrol(v.client(), tok[1]); err != nil {
		t.Fatalf("enrol again: %v", err)
	}
	wantReleased(t, m, v.release(m))
	if out, err = cli(t, "", "device", "mode", "db-03", "approve", "--socket", v.sock); err != nil || !strings.Contains(out, "approve") {
		t.Fatalf("mode: %v\n%s", err, out)
	}
	req, res, err := m.Release(v.client())
	if err != nil || res.Status != vaultproto.StatusPending {
		t.Fatalf("approve mode: %v %+v", err, res)
	}
	if out, err = cli(t, "", "requests", "--socket", v.sock); err != nil || !strings.Contains(out, req.RequestID) {
		t.Fatalf("requests: %v\n%s", err, out)
	}
	if out, err = cli(t, "", "request", "approve", req.RequestID, "--socket", v.sock); err != nil || !strings.Contains(out, "approved") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	res, err = v.client().Send(req)
	if err != nil {
		t.Fatal(err)
	}
	wantReleased(t, m, res)
	cli(t, "", "device", "mode", "db-03", "auto", "--socket", v.sock)
	if out, err = cli(t, "", "audit", "--socket", v.sock); err != nil || !strings.Contains(out, "released") || !strings.Contains(out, "approve  done") {
		t.Fatalf("audit: %v\n%s", err, out)
	}
	if _, err = cli(t, "", "device", "show", "nothing", "--socket", v.sock); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatalf("show an unknown device: %v", err)
	}

	// The vault boots in another state: denied with advice, until approved - beside
	// the running serve, with the PIN; a wrong one is refused.
	fakeTPM(v.tpm).Extend(15, "a volume opened")
	res = v.release(m)
	if res.Status != vaultproto.StatusDenied || res.Reason != approval.ErrDue.Error() {
		t.Fatalf("after the vault's boot changed: %+v", res)
	}
	if out, err := cli(t, "", "approvals", "--dir", v.dir); err != nil || !strings.Contains(out, "No approval covers") {
		t.Fatalf("approvals while due: %v\n%s", err, out)
	}
	if _, err := cli(t, "999999\n", "approve", "--dir", v.dir); !errors.Is(err, keys.ErrWrongPIN) {
		t.Fatalf("approve with a wrong PIN: %v", err)
	}
	out, err = cli(t, testPIN+"\n", "approve", "--dir", v.dir)
	if err != nil || !strings.Contains(out, "PCR 15  MOVED") || !strings.Contains(out, "PCR  7  the same") || !strings.Contains(out, "counter 2") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	wantReleased(t, m, v.release(m))
	if out, err := cli(t, "", "approvals", "--dir", v.dir); err != nil || strings.Count(out, "yes: in use") != 1 || !strings.Contains(out, "\n") {
		t.Fatalf("approvals: %v\n%s", err, out)
	}
	// The backup checks; one with a typo, or another vault's, does not.
	if out, err := cli(t, strings.ToLower(v.backup)+"\n", "backup", "check", "--dir", v.dir); err != nil || !strings.Contains(out, "is this vault's") {
		t.Fatalf("backup check: %v\n%s", err, out)
	}
	typo := []byte(v.backup)
	typo[0] = map[bool]byte{true: 'B', false: 'A'}[typo[0] == 'A']
	if _, err := cli(t, string(typo)+"\n", "backup", "check", "--dir", v.dir); !errors.Is(err, keys.ErrNotABackup) {
		t.Fatalf("a backup with a typo: %v", err)
	}
	if _, err := cli(t, initVault(t).backup+"\n", "backup", "check", "--dir", v.dir); !errors.Is(err, keys.ErrNotTheBackup) {
		t.Fatalf("another vault's backup: %v", err)
	}
	v.stop()

	// The operator interface: config set refuses while serve runs, and
	// takes effect at its next start.
	v.start()
	if _, err := cli(t, "", "config", "set", "operator-listen", opAddr, "--dir", v.dir); !errors.Is(err, state.ErrLocked) {
		t.Fatalf("config set while serving: %v", err)
	}
	out, err = cli(t, "", "operator", "add", "alice", "--socket", v.sock)
	if err != nil || !strings.Contains(out, "The operator interface is off") || !strings.Contains(out, "tls root > vault-ca.pem") {
		t.Fatalf("operator add while off: %v\n%s", err, out)
	}
	cli(t, "", "operator", "remove", "alice", "--socket", v.sock)
	v.stop()
	if _, err := cli(t, "", "config", "set", "operator-listen", "nonsense", "--dir", v.dir); err == nil {
		t.Fatal("a bad address was accepted")
	}
	if out, err := cli(t, "", "config", "set", "operator-listen", opAddr, "--dir", v.dir); err != nil || !strings.Contains(out, opAddr) {
		t.Fatalf("config set: %v\n%s", err, out)
	}
	v.start()
	alice := v.operator("alice")
	v.operator("bob")
	if out, err := cli(t, "", "operators", "--socket", v.sock); err != nil || !strings.Contains(out, "alice") || !strings.Contains(out, "bob") {
		t.Fatalf("operators: %v\n%s", err, out)
	}
	p := v.enrolWith("db-04", true)
	if out, err := cli(t, "", "device", "show", "db-04", "--socket", v.sock); err != nil || !strings.Contains(out, "pepper:          yes") || !strings.Contains(out, "mode:            approve") {
		t.Fatalf("show a pepper device: %v\n%s", err, out)
	}
	if _, err := cli(t, "", "device", "mode", "db-04", "auto", "--socket", v.sock); err == nil || !strings.Contains(err.Error(), "pepper") {
		t.Fatalf("mode auto on a pepper device: %v", err)
	}
	res = approve(t, v, alice, p, `{"pepper":"s3cret"}`)
	wantReleased(t, p, res)
	if got, err := p.OpenPepper(res.Pepper); err != nil || got != "s3cret" {
		t.Fatalf("released pepper %q: %v", got, err)
	}
	if out, err := cli(t, "", "audit", "--socket", v.sock); err != nil || !strings.Contains(out, "approve  done  "+hex.EncodeToString(p.DeviceID)+" (db-04)") || !strings.Contains(out, "by alice") || strings.Contains(out, "s3cret") {
		t.Fatalf("audit: %v\n%s", err, out)
	}
	if out, err := cli(t, "", "operator", "remove", "alice", "--socket", v.sock); err != nil || !strings.Contains(out, "removed") {
		t.Fatalf("operator remove: %v\n%s", err, out)
	}
	if code, _, _ := alice.Do("GET", "/v1/requests", ""); code != 401 {
		t.Fatalf("a removed operator: %d", code)
	}
	v.stop()

	// An approval is of at least one PCR.
	if _, err := cli(t, "", "init", "--dir", filepath.Join(t.TempDir(), "x"), "--pcrs", ""); err == nil || !strings.Contains(err.Error(), "at least one PCR") {
		t.Fatalf("init without PCRs: %v", err)
	}
}

func TestParsePCRs(t *testing.T) {
	for in, want := range map[string]string{"7": "7", "14, 7,0,7": "0,7,14", "": "none"} {
		got, err := parsePCRs(in)
		if err != nil || view.PCRs(got) != want {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"24", "x", "-1"} {
		if _, err := parsePCRs(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	if out, err := cli(t, "", "help"); err != nil || !strings.Contains(out, "token create") {
		t.Fatalf("help: %v", err)
	}
}

// The queue answered on the vault's CLI: 'request approve' asks a pepper
// device's pepper and sends it with the approval; 'requests answer' goes
// through what waits - deny, skip, approve with the pepper - and says when
// nothing does.
func TestCLIAnswersTheQueue(t *testing.T) {
	v := initVault(t)
	v.start()
	defer v.stop()
	p := v.enrolWith("db-05", true)
	pending := func() *vaultproto.ReleaseRequest {
		t.Helper()
		req, res, err := p.Release(v.client())
		if err != nil || res.Status != vaultproto.StatusPending {
			t.Fatalf("not pending: %v %+v", err, res)
		}
		return req
	}

	if out, err := cli(t, "", "requests", "answer", "--socket", v.sock); err != nil || !strings.Contains(out, "No release waits") {
		t.Fatalf("an empty queue: %v\n%s", err, out)
	}

	req := pending()
	if _, err := cli(t, "\n", "request", "approve", req.RequestID, "--socket", v.sock); err == nil || !strings.Contains(err.Error(), "pepper") {
		t.Fatalf("an approval without the pepper: %v", err)
	}
	if out, err := cli(t, "s3cret pepper\n", "request", "approve", req.RequestID, "--socket", v.sock); err != nil || !strings.Contains(out, "approved") {
		t.Fatalf("request approve: %v\n%s", err, out)
	}
	res, err := v.client().Send(req)
	if err != nil {
		t.Fatal(err)
	}
	wantReleased(t, p, res)
	if got, err := p.OpenPepper(res.Pepper); err != nil || got != "s3cret pepper" {
		t.Fatalf("the pepper the CLI sent: %q %v", got, err)
	}

	// The queue, one by one: skipped stays, denied is denied, approved with
	// the pepper is released.
	req = pending()
	if out, err := cli(t, "s\n", "requests", "answer", "--socket", v.sock); err != nil || !strings.Contains(out, "db-05") || !strings.Contains(out, "with a pepper") || !strings.Contains(out, "skipped") {
		t.Fatalf("skip: %v\n%s", err, out)
	}
	if out, err := cli(t, "x\nd\n", "requests", "answer", "--socket", v.sock); err != nil || !strings.Contains(out, "denied") {
		t.Fatalf("deny: %v\n%s", err, out)
	}
	if res, _ := v.client().Send(req); res == nil || res.Status != vaultproto.StatusDenied {
		t.Fatalf("after the denial: %+v", res)
	}
	req = pending()
	if out, err := cli(t, "a\ns3cret pepper\n", "requests", "answer", "--socket", v.sock); err != nil || !strings.Contains(out, "approved") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	res, err = v.client().Send(req)
	if err != nil {
		t.Fatal(err)
	}
	wantReleased(t, p, res)
	if out, err := cli(t, "", "audit", "--socket", v.sock); err != nil || strings.Contains(out, "s3cret") {
		t.Fatalf("the audit: %v\n%s", err, out)
	}
}

// The CLI's three places say Secure Boot's state; every state but on with the word
// WARNING, for where there is no colour.
func secureBootInTheCLI(t *testing.T, v *vault, m *vaulttest.Machine) {
	t.Helper()
	for _, tc := range []struct {
		state, table, line string
	}{
		{attest.SecureBootOn, " on\n", "secure boot:     Secure Boot on"},
		{attest.SecureBootOff, "OFF\n", "secure boot:     WARNING: Secure Boot OFF"},
		{attest.SecureBootSetupMode, "SETUP-MODE\n", "secure boot:     WARNING: Secure Boot in SETUP MODE"},
		{"no log", "NOT-ESTABLISHED\n", "secure boot:     WARNING: Secure Boot NOT ESTABLISHED"},
	} {
		if tc.state == "no log" {
			m.TPM.PCR7Chain = nil
		} else {
			m.TPM.SetSecureBoot(tc.state)
		}
		m.Approve()
		if res := v.release(m); tc.state == attest.SecureBootOn {
			wantReleased(t, m, res)
		} else if res.Status != vaultproto.StatusDenied || !strings.Contains(res.Reason, "this vault releases only to a boot with Secure Boot on") {
			t.Errorf("%s: %s, %s", tc.state, res.Status, res.Reason)
		}
		out, err := cli(t, "", "devices", "--dir", v.dir)
		if err != nil || !strings.Contains(out, tc.table) {
			t.Errorf("%s: devices: %v\n%s", tc.state, err, out)
		}
		if out, err = cli(t, "", "device", "show", "db-03", "--socket", v.sock); err != nil || !strings.Contains(out, tc.line) {
			t.Errorf("%s: device show: %v\n%s", tc.state, err, out)
		}
		out, err = cli(t, "", "audit", "--socket", v.sock)
		lines := strings.Split(strings.TrimSpace(out), "\n")
		last := lines[len(lines)-1]
		on := tc.state == attest.SecureBootOn
		if err != nil || strings.Contains(last, "released") != on || strings.Contains(last, "denied") == on || strings.Contains(last, "WARNING") == on {
			t.Errorf("%s: audit: %v\n%s", tc.state, err, last)
		}
	}
	m.TPM.SetSecureBoot(attest.SecureBootOn)
	m.Approve()
}

// restoreInto restores v's master from its backup into the TPM at path, in v's state
// directory (as if restored from a backup of it): the machines enrolled before are
// released to as before.
func restoreInto(t *testing.T, v *vault, path string) {
	t.Helper()
	d := state.Dir{Path: v.dir}
	cfg, err := d.Config()
	if err != nil {
		t.Fatal(err)
	}
	cfg.TPM = path
	if err := d.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	out, err := cli(t, v.backup+"\n"+testPIN+"\n"+testPIN+"\n", "init", "--restore", "--dir", v.dir)
	if err != nil || !strings.Contains(out, "Restored the vault's master") {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	v.tpm = path
}

// The TPM is lost: the backup and the state directory make the vault again in another
// TPM, and every machine is released to as before; another vault's backup is refused.
func TestRestore(t *testing.T) {
	v := initVault(t)
	v.start()
	m := v.enrol("db-03")
	wantReleased(t, m, v.release(m))
	v.stop()

	other := initVault(t)
	if _, err := cli(t, other.backup+"\n", "init", "--restore", "--dir", v.dir); !errors.Is(err, keys.ErrNotTheBackup) {
		t.Fatalf("another vault's backup: %v", err)
	}
	restoreInto(t, v, "fake:"+t.TempDir())
	if a, _ := (state.Dir{Path: v.dir}).Approvals(); len(a) != 1 {
		t.Fatalf("the approvals after a restore: %d", len(a))
	}
	v.start()
	wantReleased(t, m, v.release(m))
}
