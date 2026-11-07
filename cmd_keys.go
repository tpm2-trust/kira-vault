package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/tpm2-trust/go-tui-slim/secret"

	"github.com/tpm2-trust/kira-vault/internal/approval"
	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/state"
	"github.com/tpm2-trust/kira-vault/internal/view"
)

// The vault's keys at the command line: the restore of the master from its backup,
// an approval of the vault's boot state, the approvals, the backup's check. approve
// and approvals work beside a running serve: they take no lock, and serve reads the
// approvals at each release.

// cmdRestore is init --restore: the master from its backup into this TPM, in a state
// directory restored from a backup (its devices' r_dev and records), under a new
// approval key and counter, and a first approval of the boot state as it is.
func cmdRestore(d state.Dir, ask *asker, stdout, stderr io.Writer) error {
	unlock, err := d.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := d.Config()
	if err != nil {
		return fmt.Errorf("%w (init --restore needs the state directory restored from a backup first)", err)
	}
	old, err := d.Master()
	if err != nil {
		return err
	}
	if err := reachable(cfg.TPM, cfg.AdminSocket); err != nil {
		return err
	}
	typed, err := ask.secret("The backup of the vault's master key:")
	if err != nil {
		return err
	}
	master, err := keys.ParseBackup(typed)
	secret.Wipe(typed)
	if err != nil {
		return err
	}
	defer secret.Wipe(master)
	if err := keys.CheckBackup(master, &old.Master); err != nil {
		return err
	}
	t := newTPM(cfg.TPM)
	if err := checkEvidence(t, d.Path, cfg.PCRs, stderr); err != nil {
		return err
	}
	pin, err := askNewPIN(ask)
	if err != nil {
		return err
	}
	defer secret.Wipe(pin)
	m, a, err := makeKeys(t, master, pin, cfg.PCRs)
	if err != nil {
		return err
	}
	if err := d.ClearApprovals(); err != nil {
		return err
	}
	if err := d.SaveMaster(m); err != nil {
		return err
	}
	if err := d.SaveApproval(a); err != nil {
		return err
	}
	if err := logOnce(d, state.Entry{Event: "restore", Actor: "admin", Result: "done", Detail: fmt.Sprintf("the master into %s, approved at counter %d", cfg.TPM, a.Counter)}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Restored the vault's master into the TPM %s, under a new approval PIN; the boot state\nas it is now is approved. The machines enrolled before are released to as before.\n", cfg.TPM)
	return nil
}

// keysDir is the state directory of a command of the vault's keys, and its pieces.
func keysDir(name string, args []string, stderr io.Writer) (state.Dir, *state.Config, *state.Master, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	pos, err := parse(fs, args)
	if err != nil {
		return state.Dir{}, nil, nil, nil, err
	}
	d := state.Dir{Path: *dir}
	cfg, err := d.Config()
	if err != nil {
		return d, nil, nil, nil, err
	}
	m, err := d.Master()
	return d, cfg, m, pos, err
}

// cmdApprove approves the vault's boot state as it is: what moved since the last
// approval, the logs' verdicts, then the PIN. Every earlier approval stops opening the
// master (the counter).
func cmdApprove(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	d, cfg, m, pos, err := keysDir("approve", args, stderr)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("approve takes no arguments, got %q", pos)
	}
	t := newTPM(cfg.TPM)
	live, err := approval.ReadLive(t, cfg.PCRs)
	if err != nil {
		return err
	}
	approvals, err := d.Approvals()
	if err != nil {
		return err
	}
	if a, err := approval.Current(live, approvals); err == nil {
		fmt.Fprintf(stdout, "The vault's boot state is approved already (%s, counter %d): nothing to approve.\n", a.Time.Local().Format(time.DateTime), a.Counter)
		return nil
	}
	if len(approvals) > 0 {
		last := approvals[0]
		fmt.Fprintf(stdout, "Since the last approval (%s, counter %d):\n", last.Time.Local().Format(time.DateTime), last.Counter)
		moved := live.Moved(last)
		for i, p := range live.PCRs {
			was := "-"
			for j, q := range last.PCRs {
				if q == p && j < len(last.Values) {
					was = hex.EncodeToString(last.Values[j])
				}
			}
			mark := "the same"
			for _, q := range moved {
				if q == p {
					mark = "MOVED"
				}
			}
			fmt.Fprintf(stdout, "  PCR %2d  %-8s  %s\n          now       %s\n", p, mark, was, hex.EncodeToString(live.Values[i]))
		}
		if len(moved) == 0 {
			fmt.Fprintln(stdout, "  the PCRs as approved; the counter moved on (an approval since, or a restore)")
		}
	}
	if err := checkEvidence(t, d.Path, cfg.PCRs, stderr); err != nil {
		return err
	}
	names, err := m.KeyNames()
	if err != nil {
		return err
	}
	ask := newAsker(stdin, stderr)
	pin, err := ask.secret("Approval PIN:")
	if err != nil {
		return err
	}
	defer secret.Wipe(pin)
	a, err := t.Approve(&m.ApprovalKeys[0].Key, names, pin, cfg.PCRs)
	if err != nil {
		logOnce(d, state.Entry{Event: "approve-state", Actor: "admin", Result: "refused", Detail: err.Error()})
		return err
	}
	if err := d.SaveApproval(a); err != nil {
		return err
	}
	if err := logOnce(d, state.Entry{Event: "approve-state", Actor: "admin", Result: "done", Detail: fmt.Sprintf("PCRs %s at counter %d", view.PCRs(cfg.PCRs), a.Counter)}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Approved the vault's boot state: PCRs %s as they are, counter %d. Every earlier\napproval no longer opens the master.\n", view.PCRs(cfg.PCRs), a.Counter)
	return nil
}

// cmdApprovals lists the approvals, the newest first, and which covers the live state.
func cmdApprovals(args []string, stdout, stderr io.Writer) error {
	d, cfg, _, pos, err := keysDir("approvals", args, stderr)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("approvals takes no arguments, got %q", pos)
	}
	approvals, err := d.Approvals()
	if err != nil {
		return err
	}
	live, lerr := approval.ReadLive(newTPM(cfg.TPM), cfg.PCRs)
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "APPROVED\tCOUNTER\tPCRS\tLIVE\tKEY")
	for _, a := range approvals {
		state := "-"
		switch {
		case lerr != nil:
			state = "?"
		case live.Covers(a):
			state = "yes: in use"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", a.Time.Local().Format(time.DateTime), a.Counter, view.PCRs(a.PCRs), state, hex.EncodeToString(a.KeyName)[:16])
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if lerr != nil {
		return fmt.Errorf("the live state: %w", lerr)
	}
	if _, err := approval.Current(live, approvals); errors.Is(err, approval.ErrDue) {
		fmt.Fprintln(stdout, "\nNo approval covers the live boot state: kira-vault approve.")
	}
	return nil
}

// cmdBackup is 'backup check': the backup typed in rebuilds this vault's master.
func cmdBackup(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	_, _, m, pos, err := keysDir("backup", args, stderr)
	if err != nil {
		return err
	}
	if len(pos) != 1 || pos[0] != "check" {
		return errors.New("usage: kira-vault backup check [--dir DIR]")
	}
	typed, err := newAsker(stdin, stderr).secret("The backup of the vault's master key:")
	if err != nil {
		return err
	}
	master, err := keys.ParseBackup(typed)
	secret.Wipe(typed)
	if err != nil {
		return err
	}
	defer secret.Wipe(master)
	if err := keys.CheckBackup(master, &m.Master); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "The backup is this vault's master key.")
	return nil
}
