package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tpm2-trust/go-tui-slim/secret"

	"github.com/tpm2-trust/kira-vault/internal/approval"
	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
	"github.com/tpm2-trust/kira-vault/internal/tlsutil"
	"github.com/tpm2-trust/kira-vault/internal/view"
)

// ── init ─────────────────────────────────────────────────────────────────

func cmdInit(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	listen := fs.String("listen", ":8443", "machine-facing HTTPS address")
	pubURL := fs.String("url", "", "the URL machines reach the vault at (default https://HOSTNAME:PORT)")
	pcrsFlag := fs.String("pcrs", "7,15", "the vault's own PCRs its approvals are of (SHA-256 bank)")
	tpmPath := fs.String("tpm", state.DefaultTPM, "the vault's TPM")
	sock := fs.String("admin-socket", state.DefaultAdminSocket, "the admin interface's Unix socket")
	opListen := fs.String("operator-listen", "", "the operator interface's HTTPS address (default: off)")
	restore := fs.Bool("restore", false, "restore the master from its backup into this TPM, in a state directory restored from a backup")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("init takes no arguments, got %q", pos)
	}
	ask := newAsker(stdin, stderr)
	if *restore {
		return cmdRestore(state.Dir{Path: *dir}, ask, stdout, stderr)
	}
	pcrs, err := parsePCRs(*pcrsFlag)
	if err != nil {
		return err
	}
	if len(pcrs) == 0 {
		return errors.New("--pcrs: an approval is of the vault's boot state - at least one PCR (7,15 by default)")
	}
	if err := reachable(*tpmPath, *sock); err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return fmt.Errorf("--listen %q: %w", *listen, err)
	}
	if err := checkOperatorListen(*opListen, *listen); err != nil {
		return err
	}
	if *pubURL == "" {
		host, err := os.Hostname()
		if err != nil {
			return err
		}
		*pubURL = "https://" + net.JoinHostPort(host, port)
	}
	u, err := url.Parse(*pubURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("--url %q: an https URL with a host", *pubURL)
	}
	*pubURL = strings.TrimRight(*pubURL, "/")

	d := state.Dir{Path: *dir}
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if d.Initialised() {
		return fmt.Errorf("%s holds a vault already", *dir)
	}

	// What the first approval approves, checked before anything is made.
	t := newTPM(*tpmPath)
	if err := checkEvidence(t, *dir, pcrs, stderr); err != nil {
		return err
	}
	pin, err := askNewPIN(ask)
	if err != nil {
		return err
	}
	defer secret.Wipe(pin)
	master, err := secret.LockedBuffer(keys.MasterSize)
	if err != nil {
		return err
	}
	master = master[:keys.MasterSize]
	defer secret.Wipe(master)
	if _, err := rand.Read(master); err != nil {
		return err
	}
	m, a, err := makeKeys(t, master, pin, pcrs)
	if err != nil {
		return err
	}

	if err := d.Create(); err != nil {
		return err
	}
	now := time.Now()
	if err := tlsutil.Write(d, u.Hostname(), now); err != nil {
		return err
	}
	certs, err := tlsutil.Load(d, func() time.Time { return now })
	if err != nil {
		return err
	}
	pinTLS := certs.Pin()
	cfg := &state.Config{Listen: *listen, URL: *pubURL, PCRs: pcrs, TPM: *tpmPath, AdminSocket: *sock, OperatorListen: *opListen}
	if err := d.SaveMaster(m); err != nil {
		return err
	}
	if err := d.SaveApproval(a); err != nil {
		return err
	}
	if err := d.SaveConfig(cfg); err != nil {
		return err
	}
	if err := logOnce(d, state.Entry{Event: "init", Actor: "admin", Result: "done", Detail: fmt.Sprintf("url %s, PCRs %s, approved at counter %d", cfg.URL, view.PCRs(pcrs), a.Counter)}); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Initialised the vault in %s.\n\n", *dir)
	fmt.Fprintf(stdout, "  URL:   %s\n  pin:   %s  (its root's key)\n  root:  kira-vault tls root   (for the machines' %s, and curl --cacert)\n  PCRs:  %s (SHA-256), approved as they are now\n  TPM:   %s\n", cfg.URL, pinTLS, "/etc/kira/vault-ca.pem", view.PCRs(pcrs), cfg.TPM)
	if u := server.OperatorURL(cfg); u != "" {
		fmt.Fprintf(stdout, "  operator interface: %s (tokens: kira-vault operator add NAME)\n", u)
	}
	fmt.Fprintln(stdout)
	if err := showBackup(master, ask, stdout); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Next: systemctl enable --now kira-vault, then kira-vault token create --name NAME.")
	return nil
}

// askNewPIN asks for a new approval PIN, twice; the caller wipes it.
func askNewPIN(ask *asker) ([]byte, error) {
	for {
		pin, err := ask.secret("Approval PIN (approves the vault's boot state; the TPM counts wrong ones):")
		if err != nil {
			return nil, err
		}
		if len(pin) < minPIN {
			secret.Wipe(pin)
			fmt.Fprintf(ask.out, "At least %d characters.\n", minPIN)
			continue
		}
		again, err := ask.secret("The same PIN again:")
		if err != nil {
			secret.Wipe(pin)
			return nil, err
		}
		same := subtle.ConstantTimeCompare(pin, again) == 1
		secret.Wipe(again)
		if same {
			return pin, nil
		}
		secret.Wipe(pin)
		fmt.Fprintln(ask.out, "Not the same: again.")
	}
}

// minPIN is the shortest approval PIN taken.
const minPIN = 6

// makeKeys makes the vault's keys in its TPM: the approval key behind pin, the
// counter, the master imported under their policy, and the first approval of pcrs as
// they are.
func makeKeys(t approval.TPM, master, pin []byte, pcrs []uint8) (*state.Master, *keys.Approval, error) {
	key, err := t.CreateApprovalKey(pin)
	if err != nil {
		return nil, nil, err
	}
	m := &state.Master{ApprovalKeys: []state.ApprovalKey{{Kind: "tpm", Key: *key}}}
	names, err := m.KeyNames()
	if err != nil {
		return nil, nil, err
	}
	if err := t.DefineCounter(names); err != nil {
		return nil, nil, err
	}
	policy, err := keys.MasterPolicy(names)
	if err != nil {
		return nil, nil, err
	}
	mb, err := t.ImportMaster(master, policy)
	if err != nil {
		return nil, nil, err
	}
	m.Master = *mb
	a, err := t.Approve(key, names, pin, pcrs)
	if err != nil {
		return nil, nil, err
	}
	return m, a, nil
}

// showBackup shows the backup once, from bytes; on a terminal it asks its last group
// back, so that it is written down before anything goes on.
func showBackup(master []byte, ask *asker, stdout io.Writer) error {
	b, err := keys.EncodeBackup(master)
	if err != nil {
		return err
	}
	defer secret.Wipe(b)
	fmt.Fprint(stdout, "The backup of the vault's master key - shown this once: write it down and keep it\noffline. With it and a backup of the state directory, init --restore makes the vault\nagain in another TPM; without it, a lost TPM is every machine's recovery passphrase.\n\n    ")
	stdout.Write(b)
	fmt.Fprint(stdout, "\n\n")
	if f, ok := ask.in.(*os.File); !ok || !isTerminal(f) {
		return nil
	}
	last := b[bytes.LastIndexByte(b, '-')+1:]
	for {
		typed, err := ask.secret("Its last group, to show it is written down:")
		if err != nil {
			return err
		}
		ok := subtle.ConstantTimeCompare(bytes.ToUpper(bytes.TrimSpace(typed)), last) == 1
		secret.Wipe(typed)
		if ok {
			fmt.Fprint(stdout, "\033[H\033[2J\033[3J") // the backup off the screen and its scrollback
			return nil
		}
		fmt.Fprintln(ask.out, "Not its last group: look again.")
	}
}

// checkEvidence refuses an approval of pcrs the vault host's logs do not support, and
// says the notes beside one they do.
func checkEvidence(t approval.TPM, dir string, pcrs []uint8, stderr io.Writer) error {
	live, err := t.PCRs([]uint8{7, 15})
	if err != nil {
		return fmt.Errorf("the TPM: %w", err)
	}
	refusals, notes := gatherEvidence(dir, live[0], live[1]).Refusals(pcrs)
	for _, n := range notes {
		fmt.Fprintln(stderr, "Note:", n)
	}
	if len(refusals) > 0 {
		return fmt.Errorf("this boot state is not approved:\n  %s", strings.Join(refusals, "\n  "))
	}
	return nil
}

// logOnce writes one audit entry from a command that runs without serve.
func logOnce(d state.Dir, e state.Entry) error {
	a, err := state.OpenAudit(d.AuditPath(), nil)
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Log(e)
}

// ── serve ────────────────────────────────────────────────────────────────

func cmdServe(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return fmt.Errorf("serve takes no arguments, got %q", pos)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, state.Dir{Path: *dir}, stderr, nil)
}

// serve runs both interfaces until ctx ends. ready, when given, is closed
// once both listen.
func serve(ctx context.Context, d state.Dir, stderr io.Writer, ready chan<- struct{}) error {
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := d.Config()
	if err != nil {
		return err
	}
	certs, err := tlsutil.Load(d, time.Now)
	if err != nil {
		return err
	}
	pin := certs.Pin()
	audit, err := state.OpenAudit(d.AuditPath(), nil)
	if err != nil {
		return err
	}
	defer audit.Close()
	logger := log.New(stderr, "", 0)
	if _, err := d.Master(); err != nil {
		return err
	}
	// The start check: a selection with PCR 15 rests on the state directory's
	// encrypted volume, whatever measured it.
	if slices.Contains(cfg.PCRs, 15) {
		if _, err := checkEncrypted(d.Path); err != nil {
			return fmt.Errorf("the state directory %s is %w: the vault's PCR 15 says nothing of it", d.Path, err)
		}
	}
	t := newTPM(cfg.TPM)
	live, err := approval.ReadLive(t, cfg.PCRs)
	if err != nil {
		return fmt.Errorf("the vault's TPM %s: %w", cfg.TPM, err)
	}
	if approvals, err := d.Approvals(); err != nil {
		return err
	} else if _, err := approval.Current(live, approvals); err != nil {
		logger.Printf("%v: nothing is released until then", err)
	}
	srv := server.New(server.Options{Dir: d, Config: cfg, Keys: &approval.Keys{TPM: t, Dir: d, PCRs: cfg.PCRs}, Audit: audit, Pin: pin, Log: logger})

	base := func(net.Listener) context.Context { return ctx }

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	machine := &http.Server{
		Handler:           srv.MachineHandler(),
		TLSConfig:         certs.ServerConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          logger,
		BaseContext:       base,
	}

	if err := os.MkdirAll(filepath.Dir(cfg.AdminSocket), 0o700); err != nil {
		return err
	}
	os.Remove(cfg.AdminSocket) // left by a serve that is gone: the lock is ours
	old := syscall.Umask(0o177)
	adminLn, err := net.Listen("unix", cfg.AdminSocket)
	syscall.Umask(old)
	if err != nil {
		ln.Close()
		return err
	}
	defer os.Remove(cfg.AdminSocket)
	if err := os.Chmod(cfg.AdminSocket, 0o600); err != nil {
		return err
	}
	admin := &http.Server{Handler: srv.AdminHandler(), ReadHeaderTimeout: 10 * time.Second, ErrorLog: logger, BaseContext: base}

	// The operator interface: its own listener, so that it can be
	// firewalled apart from the machines'.
	var operator *http.Server
	var opLn net.Listener
	if cfg.OperatorListen != "" {
		if opLn, err = net.Listen("tcp", cfg.OperatorListen); err != nil {
			ln.Close()
			adminLn.Close()
			return err
		}
		operator = &http.Server{
			Handler:           srv.OperatorHandler(),
			TLSConfig:         certs.ServerConfig(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
			ErrorLog:          logger,
			BaseContext:       base,
		}
	}

	errc := make(chan error, 3)
	go func() { errc <- machine.ServeTLS(ln, "", "") }()
	go func() { errc <- admin.Serve(adminLn) }()
	if operator != nil {
		go func() { errc <- operator.ServeTLS(opLn, "", "") }()
		logger.Printf("operator interface on %s", cfg.OperatorListen)
	}
	audit.Log(state.Entry{Event: "serve", Result: "started", Detail: "listening on " + cfg.Listen})
	logger.Printf("serving %s on %s (pin %s), admin socket %s", cfg.URL, cfg.Listen, pin, cfg.AdminSocket)
	if ready != nil {
		close(ready)
	}

	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	machine.Shutdown(shut)
	admin.Shutdown(shut)
	if operator != nil {
		operator.Shutdown(shut)
	}
	audit.Log(state.Entry{Event: "serve", Result: "stopped"})
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ── config ───────────────────────────────────────────────────────────────

func checkOperatorListen(addr, listen string) error {
	if addr == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("operator-listen %q: %w", addr, err)
	}
	if addr == listen {
		return fmt.Errorf("operator-listen %q is the machines' address: give it its own", addr)
	}
	return nil
}

// cmdConfig changes config.json. It refuses while serve runs, which reads
// the configuration at its start.
// cmdTLS is 'tls root': the vault's root certificate, for the machines'
// /etc/kira/vault-ca.pem (luks enrol --ca FILE) and operators' curl
// --cacert. It only reads, also while serve runs.
func cmdTLS(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || pos[0] != "root" {
		return errors.New("usage: kira-vault tls root [--dir DIR]")
	}
	b, err := tlsutil.RootPEMOf(state.Dir{Path: *dir})
	if err != nil {
		return err
	}
	_, err = stdout.Write(b)
	return err
}

func cmdConfig(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 3 || pos[0] != "set" || pos[1] != "operator-listen" {
		return errors.New(`usage: kira-vault config set operator-listen ADDR|""`)
	}
	d := state.Dir{Path: *dir}
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := d.Config()
	if err != nil {
		return err
	}
	if err := checkOperatorListen(pos[2], cfg.Listen); err != nil {
		return err
	}
	cfg.OperatorListen = pos[2]
	if err := d.SaveConfig(cfg); err != nil {
		return err
	}
	if err := logOnce(d, state.Entry{Event: "config", Actor: "admin", Result: "done", Detail: "operator-listen " + strconv.Quote(pos[2])}); err != nil {
		return err
	}
	if pos[2] == "" {
		fmt.Fprintln(stdout, "The operator interface is off from serve's next start.")
	} else {
		fmt.Fprintf(stdout, "The operator interface listens on %s (%s) from serve's next start.\n", pos[2], server.OperatorURL(cfg))
	}
	return nil
}
