// Command kira-vault keeps the remote parts of kira's tpm+vault
// keyslots and releases each to its machine's TPM at boot, by the rules of
// kira's docs/VAULT.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/tpm2-trust/go-tui-slim/secret"

	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/kira-vault/internal/approval"
	"github.com/tpm2-trust/kira-vault/internal/bootstate"
	"github.com/tpm2-trust/kira-vault/internal/keys"
)

const usage = `kira-vault keeps the remote parts of kira's tpm+vault keyslots
and releases each to its machine's TPM at boot (kira docs/VAULT.md).

Usage:
  kira-vault init   [--dir DIR] [--listen :8443] [--url https://HOST:8443] [--pcrs 7,15] [--tpm /dev/tpmrm0]
                         [--admin-socket PATH] [--operator-listen :8444]
  kira-vault init --restore [--dir DIR]
  kira-vault approve   [--dir DIR]
  kira-vault approvals [--dir DIR]
  kira-vault backup check [--dir DIR]
  kira-vault config set operator-listen ADDR|""   [--dir DIR]
  kira-vault serve  [--dir DIR]
  kira-vault tls root [--dir DIR]
  kira-vault status
  kira-vault token create --name NAME [--mode auto|approve] [--ttl 1h] [--replace DEVICE]
  kira-vault token list
  kira-vault token withdraw ID
  kira-vault devices
  kira-vault device show|revoke|unlock DEVICE
  kira-vault device mode DEVICE auto|approve
  kira-vault requests [answer]
  kira-vault request approve|deny ID
  kira-vault audit  [--follow]
  kira-vault operators
  kira-vault operator add|remove NAME
  kira-vault help

The vault's keys: init draws a master key, shows it once as the backup - its only
recovery secret - and imports it into the TPM, where each machine's key is derived
from it. The master works only under an approval of the vault's own boot state:
its PCRs (SHA-256 bank; --pcrs, 7 and 15 by default) as they are, signed in the TPM
with the approval key behind the approval PIN (asked twice at init; the TPM counts
wrong ones). A moved PCR - a firmware or Secure Boot update, another boot - releases
nothing until 'approve' approves the new state; an approval refuses PCR 7 without
Secure Boot on, and PCR 15 without the state directory's volume encrypted and
measured into it. Each approval makes every earlier one invalid (a counter in the
TPM). init --restore takes the backup into another TPM, in a state directory
restored from a backup; 'backup check' checks a written-down backup.

init and config work on the state directory (default /var/lib/kira-vault) and
refuse while serve runs; approve and approvals work beside it. The other commands
talk to the running serve over its admin socket (default /run/kira-vault/admin.sock;
--socket PATH, or the one in DIR's configuration with --dir DIR).

DEVICE is a device ID (hex) or a device's unique name. A revoke is final: the
device's key goes for good, and the way back is a new enrolment (token create
--replace).

requests is the queue of releases waiting for an operator; 'requests answer'
goes through it one by one - approve, deny or skip each - and 'request
approve ID' answers one. For a device enrolled with a pepper, the pepper is
asked on the terminal (without echo; one line from a pipe) and sent with
the approval.

The operator interface (off unless operator-listen is set) serves
GET /v1/requests, POST /v1/requests/{id}/approve|deny, GET /v1/devices and
GET /v1/devices/{id} over HTTPS with the vault's certificate - verified
against its root ('tls root'; curl --cacert) - to operators with a bearer
token from 'operator add'. A device enrolled with a pepper is
approved with {"pepper":"..."}.
`

// newTPM is the vault's TPM at a path; tests replace it with a software one.
var newTPM = func(path string) approval.TPM { return &keys.TPM{Path: path} }

// gatherEvidence and checkEncrypted read the vault host's logs and its state
// directory's volume; tests replace them.
var (
	gatherEvidence = bootstate.RealPaths.Gather
	checkEncrypted = bootstate.CheckEncrypted
)

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// lockProcess locks the process in memory and makes it not dumpable, before a
// command holds a secret; tests replace it.
var lockProcess = secret.LockProcess

// holdsSecrets are the commands that hold a secret: serve (the device keys, the
// peppers in the queue), init (the master, the PIN), approve (the PIN), backup (the
// master), token create and operator add (a token shown once), request and requests
// (a pepper typed).
func holdsSecrets(cmd string) bool {
	switch cmd {
	case "init", "serve", "approve", "backup", "token", "request", "requests", "operator":
		return true
	}
	return false
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "kira-vault:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("no command")
	}
	cmd, rest := args[0], args[1:]
	if holdsSecrets(cmd) {
		if err := lockProcess(); err != nil {
			return fmt.Errorf("%s holds secrets, and the process is not locked in memory: %w (the unit sets LimitMEMLOCK=infinity, a container --ulimit memlock=-1:-1)", cmd, err)
		}
	}
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	case "init":
		return cmdInit(rest, stdin, stdout, stderr)
	case "approve":
		return cmdApprove(rest, stdin, stdout, stderr)
	case "approvals":
		return cmdApprovals(rest, stdout, stderr)
	case "backup":
		return cmdBackup(rest, stdin, stdout, stderr)
	case "serve":
		return cmdServe(rest, stderr)
	case "config":
		return cmdConfig(rest, stdout, stderr)
	case "tls":
		return cmdTLS(rest, stdout, stderr)
	case "status", "token", "devices", "device", "requests", "request", "audit", "operators", "operator":
		return cmdAdmin(cmd, rest, stdin, stdout, stderr)
	}
	return fmt.Errorf("unknown command %q (kira-vault help)", cmd)
}

// parse parses flags anywhere among the arguments and returns the
// positional ones.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// parsePCRs reads "7" or "0,7,14"; "" is no PCRs.
func parsePCRs(s string) ([]uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []uint8{}, nil
	}
	seen := map[uint8]bool{}
	var out []uint8
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 || n > 23 {
			return nil, fmt.Errorf("PCR %q: a number from 0 to 23", f)
		}
		if !seen[uint8(n)] {
			seen[uint8(n)] = true
			out = append(out, uint8(n))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
