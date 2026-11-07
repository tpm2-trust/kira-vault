package control

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/tpm2-trust/go-tui-slim/panel"

	"github.com/tpm2-trust/kira-vault/internal/view"
)

// Step is one line of a section: what the panel draws, and what it runs.
type Step struct {
	panel.Step
	Key string
	Run func(c *Control) error
}

// Section is one part of the panel.
type Section struct {
	Key, Title, Intro string
	Steps             []Step
}

func good(s string) string  { return "\033[0;32m" + s + "\033[0m" }
func bad(s string) string   { return "\033[0;31m" + s + "\033[0m" }
func amber(s string) string { return "\033[0;33m" + s + "\033[0m" }
func bold(s string) string  { return "\033[1m" + s + "\033[0m" }

// Line is one judged line of the overview: green what is good, orange what is to do or
// a risk to weigh, red what is wrong, with the risk in brackets.
type Line struct {
	Label, Text string
	Judge       int // 0 good, 1 orange, 2 red, 3 a plain fact
}

const (
	judgeGood = iota
	judgeOrange
	judgeRed
	judgeFact
)

func (l Line) String() string {
	t := l.Text
	switch l.Judge {
	case judgeGood:
		t = good("✓ ") + t
	case judgeOrange:
		t = amber("• " + t)
	case judgeRed:
		t = bad("✗ " + t)
	default:
		t = "  " + t
	}
	return fmt.Sprintf("  %-15s %s", l.Label, t)
}

// Lines is the overview, judged line by line.
func Lines(f *Facts, now time.Time) []Line {
	var out []Line
	add := func(label string, judge int, format string, a ...any) {
		out = append(out, Line{Label: label, Judge: judge, Text: fmt.Sprintf(format, a...)})
	}
	if f.Root {
		add("user", judgeGood, "root")
	} else {
		add("user", judgeRed, "not root (control runs as root: the state directory and the admin socket are root's)")
	}
	switch {
	case !f.DirExists:
		add("vault", judgeOrange, "none in %s yet: Setup, Create the vault", f.Dir)
	case f.ConfigErr != nil:
		add("vault", judgeRed, "%v", f.ConfigErr)
	case f.MasterErr != nil:
		add("vault", judgeRed, "%v", f.MasterErr)
	case f.Initialised():
		add("vault", judgeGood, "%s, %s", f.Dir, f.Config.URL)
	default:
		add("vault", judgeOrange, "%s holds no vault: Setup, Create the vault", f.Dir)
	}
	if f.DirExists {
		if f.DirMode != 0o700 {
			add("state dir", judgeRed, "%s is %v, not 0700 (others read the vault's records)", f.Dir, f.DirMode)
		}
		switch {
		case f.Volume != nil:
			add("volume", judgeGood, "encrypted: %s (%s)", f.Volume.Name, f.Volume.UUID)
		default:
			add("volume", judgeRed, "the state directory: %v (a stolen disk is the vault's records; an approval refuses PCR 15)", f.VolumeErr)
		}
	}
	switch d := f.Deployment; d.Kind {
	case Unit:
		add("deployment", judgeGood, "serve runs under kira-vault.service")
	case Container:
		add("deployment", judgeGood, "serve runs in a container (%s)", strings.TrimSpace(d.Engine+" "+d.Detail))
	case Elsewhere:
		add("deployment", judgeOrange, "serve runs, neither under the unit nor in a container (%s): control does not stop or start it", d.Detail)
	default:
		j := judgeOrange
		if f.Initialised() {
			j = judgeRed
		}
		how := []string{}
		if d.Unit {
			how = append(how, "the unit is installed")
		}
		if d.Quadlet {
			how = append(how, "the Quadlet is installed")
		}
		extra := ""
		if len(how) > 0 {
			extra = " (" + strings.Join(how, ", ") + ")"
		}
		add("deployment", j, "serve does not run%s: Setup, Run it", extra)
	}
	if r := f.SecureBoot.Risk(); r != "" {
		add("Secure Boot", judgeRed, "%s (the vault host's boot is unchecked; an approval refuses PCR 7)", r)
	} else {
		add("Secure Boot", judgeGood, "on (the vault host's firmware says so; an approval checks PCR 7's events)")
	}
	if f.Config != nil {
		pcrs := f.Config.PCRs
		switch {
		case slices.Contains(pcrs, 7) && slices.Contains(pcrs, 15):
			add("selection", judgeGood, "PCRs %s: approvals due on a db/dbx update or another volume, not on a kernel update", view.PCRs(pcrs))
		case !slices.Contains(pcrs, 7):
			add("selection", judgeOrange, "PCRs %s, without 7 (an approval says nothing of Secure Boot)", view.PCRs(pcrs))
		default:
			add("selection", judgeOrange, "PCRs %s, without 15 (an approval says nothing of the state directory's volume)", view.PCRs(pcrs))
		}
	}
	if st := f.Status; st != nil && st.Keys != nil {
		k := st.Keys
		switch {
		case k.Error != "":
			add("approval", judgeRed, "the keys could not be read: %s", k.Error)
		case k.ApprovalDue:
			moved := ""
			if len(k.Moved) > 0 {
				moved = ": PCR " + view.PCRs(k.Moved) + " moved"
			}
			add("approval", judgeRed, "due%s (nothing is released: Approvals, Approve this boot state)", moved)
		default:
			add("approval", judgeGood, "in use, of %s (counter %d)", k.Approved.Local().Format(time.DateTime), k.Counter)
		}
		add("approval keys", judgeFact, "%s", strings.Join(k.ApprovalKeys, ", "))
		if t := k.TPM; t != nil {
			if t.InLockout {
				add("TPM", judgeRed, "%s, %s: in dictionary-attack lockout (no PIN is taken until it ends)", st.TPMPath, t.Manufacturer)
			} else {
				add("TPM", judgeGood, "%s, %s; wrong PINs counted %d of %d", st.TPMPath, t.Manufacturer, t.LockoutCounter, t.MaxAuthFail)
			}
		}
	} else if f.Initialised() && f.StatusErr != nil {
		add("serve", judgeRed, "%v", f.StatusErr)
	}
	if f.Config != nil {
		u, _ := url.Parse(f.Config.URL)
		host := u.Hostname()
		if f.LeafCert != nil {
			if f.LeafCert.VerifyHostname(host) != nil {
				add("certificate", judgeRed, "the leaf is not for %s (machines refuse it)", host)
			} else if left := f.LeafCert.NotAfter.Sub(now); left < 30*24*time.Hour {
				add("certificate", judgeOrange, "the leaf ends %s (serve renews it at its start)", f.LeafCert.NotAfter.Local().Format(time.DateOnly))
			} else {
				add("certificate", judgeGood, "for %s, until %s; the root until %s", host, f.LeafCert.NotAfter.Local().Format(time.DateOnly), f.RootCert.NotAfter.Local().Format(time.DateOnly))
			}
		}
		if d := f.DNS; d != nil {
			switch {
			case d.Err != nil:
				add("URL", judgeRed, "%s does not resolve (%v): machines do not reach the vault", host, d.Err)
			case !d.Local:
				add("URL", judgeOrange, "%s is %s, not an address of this host (NAT or another machine: machines reach the vault there?)", host, strings.Join(d.Addrs, ", "))
			default:
				add("URL", judgeGood, "%s is this host (%s)", host, strings.Join(d.Addrs, ", "))
			}
		}
		for _, t := range f.TLS {
			if t.Err != nil {
				add(t.Interface, judgeRed, "%s does not answer as the vault (%v)", t.Addr, t.Err)
			} else {
				add(t.Interface, judgeGood, "%s answers, verified against the root and its pin", t.Addr)
			}
		}
		switch op := f.Config.OperatorListen; {
		case op == "":
			add("operators", judgeFact, "the operator interface is off")
		case strings.HasPrefix(op, ":") || strings.HasPrefix(op, "0.0.0.0:") || strings.HasPrefix(op, "[::]:"):
			add("operators", judgeOrange, "the operator interface listens on every address (%s): firewall it to the operators' network", op)
		default:
			add("operators", judgeGood, "the operator interface on %s", op)
		}
	}
	if f.SocketErr == nil {
		switch {
		case f.SocketMode != 0o600:
			add("admin socket", judgeRed, "%s is %v, not 0600 (whoever reaches it administers the vault)", f.Socket, f.SocketMode)
		case f.SocketUID != 0 && f.Deployment.Kind != Container:
			add("admin socket", judgeRed, "%s belongs to uid %d, not root", f.Socket, f.SocketUID)
		default:
			add("admin socket", judgeGood, "%s, 0600", f.Socket)
		}
	}
	if st := f.Status; st != nil {
		j, extra := judgeGood, []string{}
		if st.Locked > 0 {
			j, extra = judgeOrange, append(extra, fmt.Sprintf("%d locked", st.Locked))
		}
		if st.Revoked > 0 {
			extra = append(extra, fmt.Sprintf("%d revoked", st.Revoked))
		}
		if st.NotSecureBoot > 0 {
			j, extra = judgeOrange, append(extra, fmt.Sprintf("%d whose last boot was not Secure Boot on (released nothing)", st.NotSecureBoot))
		}
		text := fmt.Sprintf("%d enrolled", st.Devices)
		if len(extra) > 0 {
			text += " (" + strings.Join(extra, ", ") + ")"
		}
		add("devices", j, "%s", text)
		if st.ExpiredTokens > 0 {
			add("tokens", judgeOrange, "%d unused, %d expired (Machines: withdraw them)", st.Tokens, st.ExpiredTokens)
		} else if st.Tokens > 0 {
			add("tokens", judgeFact, "%d unused", st.Tokens)
		}
		if st.PendingRequests > 0 {
			add("requests", judgeOrange, "%d waiting for an operator (Requests)", st.PendingRequests)
		}
	}
	return out
}

// sectionKeys are the sections in their order.
var sectionKeys = []struct{ key, title, intro string }{
	{"overview", "Overview", "What the vault host and its vault are now, judged line by line; each section sets one part up or runs it."},
	{"setup", "Setup", "From an empty host to a serving vault: create it (its keys in this TPM, the backup shown once), restore it into another TPM from its backup, check the backup, run it under the unit or in a container."},
	{"machines", "Machines", "Enrolling a machine is a token for it, used once by kira on the machine; each device here can be shown, set to auto or approve, unlocked, or revoked for good."},
	{"requests", "Requests", "Releases waiting for an operator: a device in approve mode, or enrolled with a pepper. A request waits 15 minutes, then is denied."},
	{"operators", "Operators", "The operator interface answers requests over HTTPS to operators with a bearer token each, on a listener of its own, off unless set."},
	{"approvals", "Approvals", "The vault releases only under an approval of its own boot state: its PCRs as they are, signed in its TPM behind the approval PIN. A moved PCR is approved again here; each approval makes the earlier ones invalid."},
	{"tools", "Tools", "Views: the commands that read the vault, run as they are. Nothing here changes anything."},
	{"reference", "Reference", "The help of every command: what control does not do by itself is done there by hand."},
}

// Model is every section with its steps, from the facts.
func Model(f *Facts) []Section {
	var out []Section
	for _, s := range sectionKeys {
		sec := Section{Key: s.key, Title: s.title, Intro: s.intro}
		switch s.key {
		case "overview":
			sec.Steps = overviewSteps(f)
		case "setup":
			sec.Steps = setupSteps(f)
		case "machines":
			sec.Steps = machineSteps(f)
		case "requests":
			sec.Steps = requestSteps(f)
		case "operators":
			sec.Steps = operatorSteps(f)
		case "approvals":
			sec.Steps = approvalSteps(f)
		case "tools":
			sec.Steps = toolSteps(f)
		case "reference":
			sec.Steps = []Step{view0("help", "Every command", "kira-vault help", "help")}
		}
		out = append(out, sec)
	}
	return out
}

// view0 is a step that runs a command that reads.
func view0(key, title, command string, args ...string) Step {
	return Step{Key: "view:" + key, Step: panel.Step{Title: title, Command: command, Danger: panel.Reads, Runnable: true,
		Explain: "Runs " + command + " and shows what it says."},
		Run: func(c *Control) error { return c.cli(args...) }}
}

func jump(key, title, state string, dirty bool) Step {
	s := Step{Key: "menu:" + key, Step: panel.Step{Title: title, Jump: key, Danger: panel.Reads}}
	if dirty {
		s.Dirty = state
	} else if state != "" {
		s.Done = state
	}
	return s
}

func overviewSteps(f *Facts) []Step {
	var out []Step
	switch {
	case !f.Initialised():
		out = append(out, jump("setup", "Setup", "", false))
	case !f.Serving():
		out = append(out, jump("setup", "Setup", "serve does not run", true))
	default:
		out = append(out, jump("setup", "Setup", "serving", false))
	}
	if f.Status != nil && f.Status.Keys != nil && f.Status.Keys.ApprovalDue {
		out = append(out, jump("approvals", "Approvals", "due: approve the vault's boot state", true))
	} else {
		out = append(out, jump("approvals", "Approvals", "", false))
	}
	pending := 0
	for _, q := range f.Requests {
		if q.State == "pending" {
			pending++
		}
	}
	if pending > 0 {
		out = append(out, jump("requests", "Requests", fmt.Sprintf("%d waiting", pending), true))
	} else {
		out = append(out, jump("requests", "Requests", "", false))
	}
	out = append(out, jump("machines", "Machines", fmt.Sprintf("%d enrolled", len(f.Devices)), false), jump("operators", "Operators", "", false))
	return out
}

func setupSteps(f *Facts) []Step {
	initd := f.Initialised()
	create := Step{Key: "init", Step: panel.Step{Title: "Create the vault", Command: "kira-vault init --dir " + f.Dir + " ...", Runnable: true,
		Explain: "Asks the URL machines reach the vault at (its certificate is made for that host alone), the address, the PCRs approvals are of (7 and 15 by default), the operator interface; then init asks the approval PIN twice, makes the master, the approval key and the counter in this TPM, approves the boot state as it is, and shows the backup once: write it down."},
		Run: (*Control).guidedInit}
	if initd {
		create.Done = "a vault in " + f.Dir
		create.Check = true
	}
	restore := Step{Key: "restore", Step: panel.Step{Title: "Restore into this TPM", Command: "kira-vault init --restore --dir " + f.Dir, Runnable: true,
		Explain: "The TPM is lost: with the state directory restored from its backup, the master's backup makes the vault again in this TPM, under a new PIN; the machines are released to as before."},
		Run: func(c *Control) error { return c.local("init", "--restore", "--dir", c.o.Dir) }}
	backup := Step{Key: "backup", Step: panel.Step{Title: "Check the backup", Command: "kira-vault backup check --dir " + f.Dir, Runnable: true,
		Explain: "Type the written-down backup: it is checked against the master in this vault, and nothing of it is kept."},
		Run: func(c *Control) error { return c.local("backup", "check", "--dir", c.o.Dir) }}
	if !initd {
		restore.Blocked = "restore the state directory from its backup first"
		backup.Blocked = "no vault yet"
	} else if f.Serving() {
		restore.Blocked = "serve runs: stop it first"
	}
	yubikey := Step{Key: "yubikey", Step: panel.Step{Title: "A YubiKey as second approval key", Blocked: "not yet: a later step of the vault"}}
	run := Step{Key: "run", Step: panel.Step{Title: "Run it", Command: "systemctl enable --now kira-vault (or kira-vault.service of the Quadlet)", Runnable: true,
		Explain: "Under the systemd unit, or in a container (podman's Quadlet: make install-container from the vault's source)."},
		Run: (*Control).runIt}
	switch {
	case !initd:
		run.Blocked = "no vault yet"
	case f.Serving():
		run.Done = "serving (" + f.Deployment.Kind + ")"
		run.Check = true
	}
	firewall := Step{Key: "firewall", Step: panel.Step{Title: "Firewall advice", Danger: panel.Reads, Runnable: true,
		Explain: "The machines' port open to the machines' networks; the operators' port, where it is on, to the operators' alone. control never edits the firewall."},
		Run: (*Control).firewall}
	return []Step{create, restore, backup, yubikey, run, firewall}
}

func machineSteps(f *Facts) []Step {
	enrol := Step{Key: "enrol", Step: panel.Step{Title: "Enrol a machine", Command: "kira-vault token create --name NAME [--mode auto|approve] [--ttl 1h] [--replace DEVICE]", Runnable: true,
		Explain: "A token for the machine, used once, and the line to run on it (kira control's vault step, or luks enrol); the vault's root written to a file for it, if you like."},
		Run: (*Control).enrol}
	if !f.Serving() {
		enrol.Blocked = "serve does not run"
	}
	out := []Step{enrol}
	for _, t := range f.Tokens {
		t := t
		st := Step{Key: "token:" + t.ID, Step: panel.Step{Title: "Token for " + t.Name + " (" + t.ID + ")", Danger: panel.Destroys, Runnable: true,
			Destroys: "the token: it enrols nothing any more", Command: "kira-vault token withdraw " + t.ID,
			Explain: fmt.Sprintf("Mode %s, valid until %s.", t.Mode, t.Expires.Local().Format(time.DateTime))},
			Run: func(c *Control) error {
				if ok, err := c.typed("withdraw", "Withdraw the token for "+t.Name); err != nil || !ok {
					return err
				}
				return c.cli("token", "withdraw", t.ID)
			}}
		if t.Expired {
			st.Dirty = "expired: withdraw it"
		}
		out = append(out, st)
	}
	for _, d := range f.Devices {
		d := d
		st := Step{Key: "device:" + d.ID, Step: panel.Step{Title: d.Name + " (" + d.ID[:8] + ")", Runnable: true,
			Command: "kira-vault device show|mode|unlock|revoke " + d.ID,
			Explain: fmt.Sprintf("Mode %s, last release %s, Secure Boot %s.", d.Mode, view.When(d.LastRelease), view.SecureBootWord(d.SecureBoot))},
			Run: func(c *Control) error { return c.device(d) }}
		switch {
		case d.Revoked:
			st.Done = "revoked"
		case d.Locked:
			st.Dirty = "locked after failed verifications"
		default:
			st.Done = view.DeviceState(&d) + ", " + d.Mode.String()
		}
		out = append(out, st)
	}
	return out
}

func requestSteps(f *Facts) []Step {
	var out []Step
	for _, q := range f.Requests {
		q := q
		switch {
		case q.State == "pending":
			pepper := ""
			if q.Pepper {
				pepper = ", with a pepper"
			}
			out = append(out, Step{Key: "request:" + q.ID, Step: panel.Step{Title: "Release of " + q.Name, Dirty: "waits until " + q.Expires.Local().Format(time.TimeOnly),
				Command: "kira-vault request approve|deny " + q.ID, Runnable: true,
				Explain: fmt.Sprintf("Generation %d, from %s%s; %s.", q.Generation, q.Remote, pepper, view.SecureBootLine(q.SecureBoot, nil))},
				Run: func(c *Control) error { return c.request(q) }})
		case q.Layout != "":
			out = append(out, Step{Key: "layout:" + q.ID, Step: panel.Step{Title: "The keyboard of " + q.Name + "'s release", Danger: panel.Reads, Runnable: true,
				Explain: "The one-time keyboard the pepper is typed through on the machine, for this boot alone: shown on Enter, never here."},
				Run: func(c *Control) error {
					fmt.Fprintf(c.out, "Type the pepper through this layout on %s, for this boot alone.\n\n", q.Name)
					view.Layout(c.out, q.KeyboardKeys, q.Layout)
					return nil
				}})
		}
	}
	if len(out) == 0 {
		out = append(out, Step{Key: "none", Step: panel.Step{Title: "No release waits for an operator", Danger: panel.Reads}})
	}
	return out
}

func operatorSteps(f *Facts) []Step {
	iface := Step{Key: "operator-listen", Step: panel.Step{Title: "The operator interface", Command: `kira-vault config set operator-listen ADDR|""`, Runnable: true,
		Explain: "Its address, or off. serve reads it at its start: control stops serve, sets it, and starts serve again (asked)."},
		Run: (*Control).operatorListen}
	if f.Config == nil {
		iface.Blocked = "no vault yet"
	} else if f.Config.OperatorListen != "" {
		iface.Done = "on " + f.Config.OperatorListen
	}
	add := Step{Key: "operator-add", Step: panel.Step{Title: "Add an operator", Command: "kira-vault operator add NAME", Runnable: true,
		Explain: "A bearer token for the operator, shown once, with the curl line it is used with."},
		Run: func(c *Control) error {
			name, err := c.p.Input("Operator", "1 to 64 letters, digits, '.', '_' or '-'.", "", nil)
			if err != nil {
				return err
			}
			return c.cli("operator", "add", name)
		}}
	if !f.Serving() {
		add.Blocked = "serve does not run"
	}
	out := []Step{iface, add}
	for _, o := range f.Operators {
		o := o
		out = append(out, Step{Key: "operator:" + o.Name, Step: panel.Step{Title: "Operator " + o.Name, Danger: panel.Destroys, Runnable: true,
			Destroys: "the operator's token: it answers nothing any more", Command: "kira-vault operator remove " + o.Name,
			Done: "since " + o.Created.Local().Format(time.DateOnly)},
			Run: func(c *Control) error {
				if ok, err := c.typed(o.Name, "Remove operator "+o.Name); err != nil || !ok {
					return err
				}
				return c.cli("operator", "remove", o.Name)
			}})
	}
	return out
}

func approvalSteps(f *Facts) []Step {
	approve := Step{Key: "approve", Step: panel.Step{Title: "Approve this boot state", Command: "kira-vault approve --dir " + f.Dir, Runnable: true,
		Explain: "Shows what moved since the last approval and what the logs say of it (Secure Boot from PCR 7's events, the state directory's volume in PCR 15), then asks the approval PIN; the TPM counts wrong ones. Every earlier approval stops opening the master."},
		Run: func(c *Control) error { return c.local("approve", "--dir", c.o.Dir) }}
	switch {
	case !f.Initialised():
		approve.Blocked = "no vault yet"
	case f.Status != nil && f.Status.Keys != nil && f.Status.Keys.ApprovalDue:
		approve.Dirty = "due: nothing is released until then"
	case f.Status != nil && f.Status.Keys != nil && f.Status.Keys.Approved != nil:
		approve.Done = "in use, of " + f.Status.Keys.Approved.Local().Format(time.DateTime)
		approve.Check = true
	}
	out := []Step{approve}
	for _, a := range f.Approvals {
		a := a
		var lines []string
		for i, p := range a.PCRs {
			if i < len(a.Values) {
				lines = append(lines, fmt.Sprintf("PCR %d = %x", p, a.Values[i]))
			}
		}
		out = append(out, Step{Key: "approval:" + a.Time.String(), Step: panel.Step{Title: "Approved " + a.Time.Local().Format(time.DateTime), Danger: panel.Reads,
			Done: fmt.Sprintf("counter %d", a.Counter), Explain: strings.Join(lines, "\n")}})
	}
	out = append(out, view0("root", "The root and its pin", "kira-vault tls root", "tls", "root", "--dir", f.Dir))
	return out
}

func toolSteps(f *Facts) []Step {
	viaSocket := func(key, title string, args ...string) Step {
		s := view0(key, title, "kira-vault "+strings.Join(args, " "), args...)
		if !f.Serving() {
			s.Blocked = "serve does not run"
		}
		return s
	}
	out := []Step{
		viaSocket("status", "Status", "status"),
		viaSocket("devices", "Devices", "devices"),
		viaSocket("requests", "Requests", "requests"),
		viaSocket("operators", "Operators", "operators"),
		viaSocket("tokens", "Unused tokens", "token", "list"),
		viaSocket("audit", "The audit log", "audit"),
		view0("approvals", "Approvals", "kira-vault approvals --dir "+f.Dir, "approvals", "--dir", f.Dir),
	}
	if !f.Initialised() {
		out[len(out)-1].Blocked = "no vault yet"
	}
	return out
}

// listenPort is a listen address's port, for the firewall's advice.
func listenPort(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return p
}
