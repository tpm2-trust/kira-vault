package control

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/tpm2-trust/go-tui-slim/panel"
	"github.com/tpm2-trust/go-tui-slim/prompt"
	"github.com/tpm2-trust/go-tui-slim/tui"

	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
)

// CLI is the vault's command line, run in-process with these streams (main.run).
type CLI func(args []string, stdin io.Reader, stdout, stderr io.Writer) error

// Options configure control.
type Options struct {
	Dir    string // the state directory
	Socket string // the admin socket; "" the configuration's
	Lines  bool   // line menus, not the full screen
	Debug  bool   // say what is run
	CLI    CLI
	In     *os.File // the terminal; nil os.Stdin
	Out    io.Writer
	Env    *Env // nil: HostEnv
	// AllowUser lets the tests run it as a user.
	AllowUser bool
}

// Control is a run of the panel.
type Control struct {
	o     Options
	env   *Env
	in    *os.File
	out   io.Writer
	p     *prompt.Prompter
	facts *Facts
	model []Section // the last drawn: what a step's index means
	tty   bool
}

// Run is control: the full screen on a terminal that has a size, line menus with
// --lines (or a terminal without one), a printout of everything without a terminal.
func Run(o Options) error {
	c := &Control{o: o, env: o.Env, in: o.In, out: o.Out}
	if c.env == nil {
		c.env = &HostEnv
	}
	if c.in == nil {
		c.in = os.Stdin
	}
	if c.out == nil {
		c.out = os.Stdout
	}
	if c.o.Dir == "" {
		c.o.Dir = state.DefaultDir
	}
	if os.Geteuid() != 0 && !o.AllowUser {
		return errors.New("control runs as root: the state directory, the admin socket and the TPM are root's (sudo kira-vault control)")
	}
	c.p = prompt.New(c.in, c.out)
	c.tty = tui.IsTerminal(c.in)
	c.facts = c.env.Fast(c.o.Dir, c.o.Socket)
	switch {
	case !c.tty:
		c.env.Slow(c.facts)
		c.printout()
		return nil
	case !c.o.Lines && !c.o.Debug && os.Getenv("TERM") != "dumb" && c.sized():
		return panel.Run(&source{c: c}, panel.Config{In: c.in, Out: c.screenOut(), Help: keysHelp,
			Loading: "Looking at the vault ...", Again: "Looking at the vault again ..."})
	}
	c.env.Slow(c.facts)
	return c.lineMenus()
}

func (c *Control) sized() bool {
	f, ok := c.out.(*os.File)
	if !ok || !tui.IsTerminal(f) {
		return false
	}
	cols, rows, ok := tui.Open(c.in, f).Size()
	return ok && cols >= 40 && rows >= 12
}

// screenOut is the terminal the panel draws on: stdout hushed (nil), or a test's.
func (c *Control) screenOut() *os.File {
	if f, ok := c.out.(*os.File); ok && f != os.Stdout {
		return f
	}
	return nil
}

const keysHelp = `Keys

  Up, Down, j, k     move in the sections, or in a section's steps
  Right, Tab, l      from the sections into the steps
  Left, h, Esc       back to the sections
  Enter              open a section; run a step (a blocked one says why)
  PgUp, PgDn         scroll the detail
  /                  search every step of every section
  r                  look at the vault again
  Ctrl-L             draw the screen again
  ?                  this help, again to close it
  q, Esc, Ctrl-C     leave

A step runs in the terminal below the screen, asks what it needs, and comes back
here. One that destroys (marked) asks for its word: the device's or operator's
name, or "withdraw".`

// ── running the CLI ─────────────────────────────────────────────────────

// adminCommands talk to serve over the admin socket.
var adminCommands = map[string]bool{"status": true, "token": true, "devices": true, "device": true, "requests": true, "request": true, "audit": true, "operators": true, "operator": true}

// cli runs a command of the vault's in-process, on the terminal; the admin socket's
// commands with the panel's socket.
func (c *Control) cli(args ...string) error {
	if len(args) > 0 && adminCommands[args[0]] && c.facts.Socket != "" {
		args = append(args, "--socket", c.facts.Socket)
	}
	if c.o.Debug {
		fmt.Fprintf(c.out, "control: kira-vault %s\n", strings.Join(args, " "))
	}
	return c.o.CLI(args, c.in, c.out, c.out)
}

// local runs a command that works on the state directory or the TPM: in-process, or -
// where serve runs in a container - in serve's container, through its engine.
func (c *Control) local(args ...string) error {
	d := c.facts.Deployment
	if d.Kind != Container {
		return c.cli(args...)
	}
	engine := d.Engine
	if engine == "" {
		engine = "podman"
	}
	return c.exec(engine, append([]string{"exec", "-it", "kira-vault", "/kira-vault"}, args...)...)
}

// exec runs a program on the terminal and says what it ran.
func (c *Control) exec(name string, args ...string) error {
	fmt.Fprintf(c.out, "\033[2m# %s %s\033[0m\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.in, c.out, c.out
	return cmd.Run()
}

// typed asks for word before a step that destroys; a wrong word is no.
func (c *Control) typed(word, what string) (bool, error) {
	got, err := c.p.Input(what+"?", fmt.Sprintf("This cannot be undone. Type %q to go on, anything else to leave it.", word), "", nil)
	if err != nil {
		return false, err
	}
	if got != word {
		fmt.Fprintln(c.out, "Left as it is.")
		return false, nil
	}
	return true, nil
}

// ── the guided actions ──────────────────────────────────────────────────

// guidedInit asks what init needs and runs it - in-process for the unit, or the
// container's form.
func (c *Control) guidedInit() error {
	host, _ := os.Hostname()
	if addrs, _ := c.env.LocalAddrs(); len(addrs) > 0 && host == "" {
		host = addrs[0].String()
	}
	fmt.Fprintln(c.out, "The vault's certificate is made for the URL's host alone: machines that reach the vault")
	fmt.Fprintln(c.out, "by another name or address refuse it, and the URL cannot change afterwards (a new vault).")
	listen, err := c.p.Input("Listen", "The machines' HTTPS address.", ":8443", func(s string) error { _, _, err := net.SplitHostPort(s); return err })
	if err != nil {
		return err
	}
	u, err := c.p.Input("URL", "The URL machines reach the vault at.", "https://"+net.JoinHostPort(host, listenPort(listen)), func(s string) error {
		if !strings.HasPrefix(s, "https://") {
			return errors.New("an https URL")
		}
		return nil
	})
	if err != nil {
		return err
	}
	pcrs, err := c.p.Input("PCRs", "The vault's own PCRs its approvals are of. 7: Secure Boot (an approval due on a db/dbx update); 15: the state directory's volume (due on another one); 11 and 4: the kernel (due on every update).", "7,15", nil)
	if err != nil {
		return err
	}
	op, err := c.p.Input("Operator interface", "Its HTTPS address, or empty for off (it can be set later).", "", nil)
	if err != nil {
		return err
	}
	args := []string{"init", "--dir", c.o.Dir, "--listen", listen, "--url", u, "--pcrs", pcrs}
	if op != "" {
		args = append(args, "--operator-listen", op)
	}
	how, err := prompt.Select(c.p, "Where it runs", "In-process here, for the systemd unit; or in a container (podman, the image localhost/kira-vault:latest from make container).",
		[]prompt.Option[string]{{Value: "unit", Label: "Here, for the unit"}, {Value: "container", Label: "In a container"}}, "unit")
	if err != nil {
		return err
	}
	if how == "unit" {
		return c.cli(args...)
	}
	run, err := containerRun(c.o.Dir)
	if err != nil {
		return err
	}
	return c.exec("podman", append(run, args[1:]...)...)
}

// containerRun is the podman run line that runs a command of the vault in its image,
// with serve's devices and volumes, its user namespace mapping the host's tss group.
func containerRun(dir string) ([]string, error) {
	g, err := user.LookupGroup("tss")
	if err != nil {
		return nil, fmt.Errorf("the host's tss group: %w", err)
	}
	return []string{"run", "--rm", "-it", "--device", "/dev/tpmrm0", "--userns", "auto:gidmapping=5000:" + g.Gid + ":1", "--group-add", "5000",
		"--ulimit", "memlock=-1:-1", "-v", dir + ":/var/lib/kira-vault:Z", "-v", "/run/kira-vault:/run/kira-vault:Z",
		"-v", "/sys/kernel/security:/sys/kernel/security:ro", "-v", "/run/log/systemd:/run/log/systemd:ro",
		"localhost/kira-vault:latest", "init"}, nil
}

// runIt starts serve: under the unit, or the Quadlet's service.
func (c *Control) runIt() error {
	d := c.facts.Deployment
	var opts []prompt.Option[string]
	if d.Unit {
		opts = append(opts, prompt.Option[string]{Value: "unit", Label: "The systemd unit (systemctl enable --now kira-vault)"})
	}
	if d.Quadlet {
		opts = append(opts, prompt.Option[string]{Value: "quadlet", Label: "The container (systemctl daemon-reload, start kira-vault)"})
	}
	if len(opts) == 0 {
		fmt.Fprintln(c.out, "Neither the unit nor the Quadlet is installed: make install (the unit) or make install-container (podman) from the vault's source.")
		return nil
	}
	how, err := prompt.Select(c.p, "Run it", "", opts, opts[0].Value)
	if err != nil {
		return err
	}
	if how == "unit" {
		return c.exec("systemctl", "enable", "--now", "kira-vault")
	}
	if err := c.exec("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return c.exec("systemctl", "start", "kira-vault")
}

// firewall says what to open, and edits nothing.
func (c *Control) firewall() error {
	if c.facts.Config == nil {
		fmt.Fprintln(c.out, "No vault yet: its ports are what init is given (8443 by default).")
		return nil
	}
	cfg := c.facts.Config
	fmt.Fprintf(c.out, "The machines' port, %s/tcp: open to the networks the machines boot in.\n", listenPort(cfg.Listen))
	if cfg.OperatorListen != "" {
		fmt.Fprintf(c.out, "The operators' port, %s/tcp: to the operators' network alone, never the machines'.\n", listenPort(cfg.OperatorListen))
	}
	fmt.Fprintf(c.out, "\nFor nftables, for example:\n  nft add rule inet filter input tcp dport %s accept\n", listenPort(cfg.Listen))
	if cfg.OperatorListen != "" {
		fmt.Fprintf(c.out, "  nft add rule inet filter input ip saddr OPERATORS-NET tcp dport %s accept\n", listenPort(cfg.OperatorListen))
	}
	return nil
}

// enrol makes a token for a machine, and offers the root as a file for it.
func (c *Control) enrol() error {
	name, err := c.p.Input("Name", "The machine's name, as the vault shows it.", "", func(s string) error {
		if s == "" {
			return errors.New("a name")
		}
		return nil
	})
	if err != nil {
		return err
	}
	mode, err := prompt.Select(c.p, "Mode", "auto: released at every verified boot; approve: an operator approves each release.",
		[]prompt.Option[string]{{Value: "auto", Label: "auto"}, {Value: "approve", Label: "approve"}}, "auto")
	if err != nil {
		return err
	}
	replace := ""
	for _, d := range c.facts.Devices {
		if d.Name == name {
			ok, err := c.p.Confirm("Enrol "+name+" again?", "A device of that name is enrolled: the token replaces it (its old enrolment goes).", true)
			if err != nil || !ok {
				return err
			}
			replace = d.ID
		}
	}
	args := []string{"token", "create", "--name", name, "--mode", mode}
	if replace != "" {
		args = append(args, "--replace", replace)
	}
	if err := c.cli(args...); err != nil {
		return err
	}
	want, err := c.p.Confirm("Write the vault's root to a file?", "For the machine's /etc/kira/vault-ca.pem (luks enrol --ca FILE).", false)
	if err != nil || !want {
		return err
	}
	path, err := c.p.Input("File", "", "vault-ca.pem", nil)
	if err != nil {
		return err
	}
	var root bytes.Buffer
	if err := c.o.CLI([]string{"tls", "root", "--dir", c.o.Dir}, c.in, &root, c.out); err != nil {
		return err
	}
	if err := os.WriteFile(path, root.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Wrote the vault's root to %s.\n", path)
	return nil
}

// device runs what can be done to one device.
func (c *Control) device(d server.DeviceView) error {
	opts := []prompt.Option[string]{{Value: "show", Label: "Show it"}}
	if !d.Revoked {
		other := map[string]string{"auto": "approve", "approve": "auto"}[d.Mode.String()]
		if !d.Pepper || other == "approve" {
			opts = append(opts, prompt.Option[string]{Value: "mode", Label: "Mode " + other})
		}
		if d.Locked {
			opts = append(opts, prompt.Option[string]{Value: "unlock", Label: "Unlock it"})
		}
		opts = append(opts, prompt.Option[string]{Value: "revoke", Label: "Revoke it, for good ⚠"})
	}
	what, err := prompt.Select(c.p, d.Name, "", opts, "show")
	if err != nil {
		return err
	}
	switch what {
	case "mode":
		return c.cli("device", "mode", d.ID, map[string]string{"auto": "approve", "approve": "auto"}[d.Mode.String()])
	case "unlock":
		return c.cli("device", "unlock", d.ID)
	case "revoke":
		if ok, err := c.typed(d.Name, "Revoke "+d.Name+": its key goes for good"); err != nil || !ok {
			return err
		}
		return c.cli("device", "revoke", d.ID)
	}
	return c.cli("device", "show", d.ID)
}

// request answers one waiting release; an approval of a pepper device asks the pepper
// (the CLI does).
func (c *Control) request(q server.RequestView) error {
	what, err := prompt.Select(c.p, "Release of "+q.Name, "", []prompt.Option[string]{
		{Value: "approve", Label: "Approve it"}, {Value: "deny", Label: "Deny it"}, {Value: "skip", Label: "Leave it waiting"}}, "skip")
	if err != nil || what == "skip" {
		return err
	}
	return c.cli("request", what, q.ID)
}

// operatorListen sets the operator interface, with serve stopped and started again.
func (c *Control) operatorListen() error {
	cfg := c.facts.Config
	addr, err := c.p.Input("Operator interface", "Its HTTPS address (a port of its own, e.g. MGMT-ADDR:8444), or empty for off.", cfg.OperatorListen, nil)
	if err != nil {
		return err
	}
	d := c.facts.Deployment
	stop, start := []string(nil), []string(nil)
	switch d.Kind {
	case Unit:
		stop, start = []string{"systemctl", "stop", "kira-vault"}, []string{"systemctl", "start", "kira-vault"}
	case Container:
		stop, start = []string{"systemctl", "stop", "kira-vault"}, []string{"systemctl", "start", "kira-vault"}
	case Elsewhere:
		return errors.New("serve runs neither under the unit nor in a container: stop it, run kira-vault config set operator-listen, and start it again by hand")
	}
	if stop != nil {
		ok, err := c.p.Confirm("Stop serve, set it, start serve again?", "Releases are refused for those seconds.", true)
		if err != nil || !ok {
			return err
		}
		if err := c.exec(stop[0], stop[1:]...); err != nil {
			return err
		}
	}
	err = c.cli("config", "set", "operator-listen", addr, "--dir", c.o.Dir)
	if start != nil {
		if serr := c.exec(start[0], start[1:]...); err == nil {
			err = serr
		}
	}
	return err
}

// ── showing it ──────────────────────────────────────────────────────────

func (c *Control) header(loading bool) string {
	host, _ := os.Hostname()
	h := "[ \033[1;33mVAULT\033[0m ] kira-vault control · " + host
	if loading {
		return h
	}
	f := c.facts
	switch {
	case !f.Initialised():
		h += " · " + amber("no vault yet")
	case !f.Serving():
		h += " · " + bad("serve does not run")
	default:
		h += " · " + good("serving ("+f.Deployment.Kind+")")
	}
	if st := f.Status; st != nil && st.Keys != nil && st.Keys.ApprovalDue {
		h += " · " + bad("approval due")
	}
	if f.SecureBoot.Risk() != "" {
		h += " · " + bad("Secure Boot not on")
	}
	return h
}

// overview is the facts' text, for the overview's detail and the printout.
func (c *Control) overview() string {
	var b strings.Builder
	b.WriteString(bold("What the vault host and the vault have") + "\n")
	for _, l := range Lines(c.facts, c.env.Now()) {
		b.WriteString(l.String() + "\n")
	}
	if c.facts.Checking {
		b.WriteString("\033[2m  (checking serve, the network ...)\033[0m\n")
	}
	return b.String()
}

// panelSections are the model as the panel draws it.
func (c *Control) panelSections(m []Section) []panel.Section {
	out := make([]panel.Section, len(m))
	for i, s := range m {
		out[i] = panel.Section{Key: s.Key, Title: s.Title, Intro: s.Intro}
		if s.Key == "overview" {
			out[i].Intro += "\n\n" + c.overview()
		}
		for _, st := range m[i].Steps {
			p := st.Step
			p.Runnable = p.Runnable && st.Run != nil
			out[i].Steps = append(out[i].Steps, p)
		}
	}
	return out
}

// runStep runs a step below the screen, and waits for a key.
func (c *Control) runStep(s Step) {
	fmt.Fprint(c.out, "\033[H\033[2J")
	fmt.Fprintf(c.out, "\n%s\n%s\n\n", bold(s.Title), s.Explain)
	if err := s.Run(c); err != nil {
		fmt.Fprintf(c.out, "\n%s %v\n", bad("Not done:"), err)
	}
	c.p.Wait("Back to control", "", "OK")
}

// source is control as the panel's Source.
type source struct{ c *Control }

func (s *source) Header(loading bool) string { return s.c.header(loading) }
func (s *source) Checking() bool             { return s.c.facts.Checking }
func (s *source) Sections(loading bool) []panel.Section {
	if loading {
		var out []panel.Section
		for _, k := range sectionKeys {
			out = append(out, panel.Section{Key: k.key, Title: k.title, Intro: k.intro})
		}
		return out
	}
	s.c.model = Model(s.c.facts)
	return s.c.panelSections(s.c.model)
}
func (s *source) Collect() <-chan func() {
	got := make(chan func(), 2)
	c := s.c
	go func() {
		defer close(got)
		f := c.env.Fast(c.o.Dir, c.o.Socket)
		fast := *f
		got <- func() { c.facts = &fast }
		c.env.Slow(f)
		got <- func() { c.facts = f }
	}()
	return got
}
func (s *source) Run(section, step int) { s.c.runStep(s.c.model[section].Steps[step]) }

// lineMenus is control in line menus: a section, then its steps.
func (c *Control) lineMenus() error {
	for {
		m := Model(c.facts)
		var opts []prompt.Option[int]
		for i, s := range m {
			opts = append(opts, prompt.Option[int]{Value: i, Label: s.Title})
		}
		fmt.Fprint(c.out, "\n"+c.header(false)+"\n\n"+c.overview())
		i, err := prompt.Select(c.p, "Section", "", opts, 0)
		if err != nil {
			return nil // cancelled: leave
		}
		sec := m[i]
		var steps []prompt.Option[int]
		for j, s := range sec.Steps {
			steps = append(steps, prompt.Option[int]{Value: j, Label: tui.StripSGR(panel.Row(s.Step, tui.GlyphsFor(tui.UTF8Locale())))})
		}
		steps = append(steps, prompt.Option[int]{Value: -1, Label: "Back"})
		fmt.Fprintf(c.out, "\n%s\n%s\n", bold(sec.Title), sec.Intro)
		j, err := prompt.Select(c.p, sec.Title, "", steps, -1)
		if err != nil || j < 0 {
			continue
		}
		s := sec.Steps[j]
		switch {
		case s.Jump != "":
			continue
		case s.Blocked != "" && s.Done == "":
			fmt.Fprintln(c.out, amber("Not possible here: "+s.Blocked))
			continue
		case s.Run == nil:
			fmt.Fprintln(c.out, s.Explain)
			continue
		}
		c.runStep(s)
		c.facts = c.env.Fast(c.o.Dir, c.o.Socket)
		c.env.Slow(c.facts)
	}
}

// printout is everything, without a terminal: the overview and every step with its
// state and command.
func (c *Control) printout() {
	fmt.Fprintln(c.out, tui.StripSGR(c.header(false)))
	fmt.Fprintln(c.out)
	fmt.Fprint(c.out, tui.StripSGR(c.overview()))
	g := tui.GlyphsFor(false)
	for _, s := range Model(c.facts) {
		if s.Key == "overview" || s.Key == "reference" {
			continue
		}
		fmt.Fprintf(c.out, "\n%s\n", s.Title)
		for _, st := range s.Steps {
			line := "  " + tui.StripSGR(panel.Row(st.Step, g))
			if st.Command != "" {
				line += "\n      " + st.Command
			}
			fmt.Fprintln(c.out, line)
		}
	}
}
