package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tpm2-trust/kira/core/vaultproto"

	"github.com/tpm2-trust/go-tui-slim/prompt"
	"github.com/tpm2-trust/go-tui-slim/secret"

	"github.com/tpm2-trust/kira-vault/internal/adminclient"
	"github.com/tpm2-trust/kira-vault/internal/secretjson"
	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
	"github.com/tpm2-trust/kira-vault/internal/view"
)

func cmdAdmin(cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	ask := newAsker(stdin, stderr)
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "state directory whose configured admin socket to use")
	socket := fs.String("socket", "", "the admin socket (default "+state.DefaultAdminSocket+")")
	name := fs.String("name", "", "token create: the machine's name")
	mode := fs.String("mode", vaultproto.ModeAuto.String(), "token create: auto or approve")
	ttl := fs.Duration("ttl", server.DefaultTokenTTL, "token create: how long the token is valid")
	replace := fs.String("replace", "", "token create: the device the token enrols again")
	follow := fs.Bool("follow", false, "audit: keep printing new lines")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if *socket == "" {
		*socket = state.DefaultAdminSocket
		if *dir != "" {
			cfg, err := (state.Dir{Path: *dir}).Config()
			if err != nil {
				return err
			}
			*socket = cfg.AdminSocket
		}
	}
	c := adminclient.New(*socket)
	want := func(n int, form string) error {
		if len(pos) != n {
			return fmt.Errorf("usage: kira-vault %s", form)
		}
		return nil
	}
	esc := url.PathEscape

	switch cmd {
	case "status":
		if err := want(0, "status"); err != nil {
			return err
		}
		var st server.StatusView
		if err := c.Do("GET", "/v1/status", nil, &st); err != nil {
			return err
		}
		view.Status(stdout, &st)
		return nil

	case "token":
		if len(pos) == 1 && pos[0] == "list" {
			var list []server.TokenView
			if err := c.Do("GET", "/v1/tokens", nil, &list); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "TOKEN\tNAME\tMODE\tEXPIRES\tREPLACES")
			for _, t := range list {
				exp := t.Expires.Local().Format(time.DateTime)
				if t.Expired {
					exp += " (expired)"
				}
				rep := t.Replace
				if rep == "" {
					rep = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Mode, exp, rep)
			}
			return tw.Flush()
		}
		if len(pos) == 2 && pos[0] == "withdraw" {
			var t server.TokenView
			if err := c.Do("DELETE", "/v1/tokens/"+esc(pos[1]), nil, &t); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Token %s for %s withdrawn: it enrols nothing any more.\n", t.ID, t.Name)
			return nil
		}
		if err := want(1, "token create --name NAME [--mode auto|approve] [--ttl 1h] [--replace DEVICE], token list, token withdraw ID"); err != nil {
			return err
		}
		if pos[0] != "create" {
			return fmt.Errorf("unknown token command %q", pos[0])
		}
		m, err := vaultproto.ParseReleaseMode(*mode)
		if err != nil {
			return err
		}
		var t server.TokenResponse
		if err := c.Do("POST", "/v1/tokens", server.TokenRequest{Name: *name, Mode: m, TTLSeconds: int(ttl.Seconds()), Replace: *replace}, &t); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Token for %s (mode %s), valid until %s:\n\n", t.Name, t.Mode, t.Expires.Local().Format(time.DateTime))
		fmt.Fprintf(stdout, "  token:  %s\n  URL:    %s\n  pin:    %s\n\n", t.Token, t.URL, t.Pin)
		fmt.Fprintf(stdout, "On the machine, as root:\n\n  %s\n", t.Command)
		return nil

	case "devices":
		if err := want(0, "devices"); err != nil {
			return err
		}
		var list []server.DeviceView
		if err := c.Do("GET", "/v1/devices", nil, &list); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "DEVICE\tNAME\tMODE\tPEPPER\tSTATE\tGENERATION\tLAST RELEASE\tSECURE BOOT")
		for _, d := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", d.ID, d.Name, d.Mode, view.YesNo(d.Pepper), view.DeviceState(&d), d.MinGeneration, view.When(d.LastRelease), view.SecureBootWord(d.SecureBoot))
		}
		return tw.Flush()

	case "device":
		if len(pos) < 2 {
			return fmt.Errorf("usage: kira-vault device show|revoke|unrevoke|unlock DEVICE, or device mode DEVICE auto|approve")
		}
		var d server.DeviceView
		switch pos[0] {
		case "show":
			if err := want(2, "device show DEVICE"); err != nil {
				return err
			}
			if err := c.Do("GET", "/v1/devices/"+esc(pos[1]), nil, &d); err != nil {
				return err
			}
		case "revoke", "unrevoke", "unlock":
			if err := want(2, "device "+pos[0]+" DEVICE"); err != nil {
				return err
			}
			if err := c.Do("POST", "/v1/devices/"+esc(pos[1])+"/"+pos[0], nil, &d); err != nil {
				return err
			}
		case "mode":
			if err := want(3, "device mode DEVICE auto|approve"); err != nil {
				return err
			}
			m, err := vaultproto.ParseReleaseMode(pos[2])
			if err != nil {
				return err
			}
			if err := c.Do("POST", "/v1/devices/"+esc(pos[1])+"/mode", server.ModeRequest{Mode: m}, &d); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown device command %q", pos[0])
		}
		view.Device(stdout, &d)
		return nil

	case "requests":
		if len(pos) == 1 && pos[0] == "answer" {
			return answerQueue(c, ask, stdout)
		}
		if err := want(0, "requests [answer]"); err != nil {
			return err
		}
		var list []server.RequestView
		if err := c.Do("GET", "/v1/requests", nil, &list); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REQUEST\tDEVICE\tNAME\tSTATE\tPEPPER\tGENERATION\tFROM\tEXPIRES\tSECURE BOOT")
		for _, q := range list {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", q.ID, q.DeviceID, q.Name, q.State, view.YesNo(q.Pepper), q.Generation, q.Remote, q.Expires.Local().Format(time.TimeOnly), view.SecureBootWord(q.SecureBoot))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		for _, q := range list {
			if q.Layout != "" {
				fmt.Fprintf(stdout, "\nRequest %s of %s: type the pepper through this layout, for this boot alone.\n", q.ID, q.Name)
				view.Layout(stdout, q.KeyboardKeys, q.Layout)
			}
		}
		return nil

	case "request":
		if err := want(2, "request approve|deny ID"); err != nil {
			return err
		}
		if pos[0] != "approve" && pos[0] != "deny" {
			return fmt.Errorf("unknown request command %q", pos[0])
		}
		q, err := decideRequest(c, ask, pos[1], pos[0] == "approve")
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Request %s of device %s: %s. The machine is answered when it asks again.\n", q.ID, q.DeviceID, q.State)
		return nil

	case "operators":
		if err := want(0, "operators"); err != nil {
			return err
		}
		var list []server.OperatorView
		if err := c.Do("GET", "/v1/operators", nil, &list); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "OPERATOR\tCREATED")
		for _, o := range list {
			fmt.Fprintf(tw, "%s\t%s\n", o.Name, o.Created.Local().Format(time.DateTime))
		}
		return tw.Flush()

	case "operator":
		if err := want(2, "operator add|remove NAME"); err != nil {
			return err
		}
		switch pos[0] {
		case "add":
			var o server.OperatorAdded
			if err := c.Do("POST", "/v1/operators", server.OperatorRequest{Name: pos[1]}, &o); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Operator %s, token (shown this once):\n\n  %s\n\n", o.Name, o.Token)
			fmt.Fprintf(stdout, "  pin:       %s (the vault's root)\n  for curl:  kira-vault tls root > vault-ca.pem, then --cacert vault-ca.pem\n", o.Pin)
			if o.URL == "" {
				fmt.Fprintln(stdout, "\nThe operator interface is off: kira-vault config set operator-listen :8444, with serve stopped.")
			} else {
				fmt.Fprintf(stdout, "  URL:       %s\n\nFor example:\n\n  %s\n", o.URL, o.Example)
			}
			return nil
		case "remove":
			if err := c.Do("DELETE", "/v1/operators/"+esc(pos[1]), nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Operator %s removed: its token no longer works.\n", pos[1])
			return nil
		}
		return fmt.Errorf("unknown operator command %q", pos[0])

	case "audit":
		if err := want(0, "audit [--follow]"); err != nil {
			return err
		}
		path := "/v1/audit"
		if *follow {
			path += "?follow=1"
		}
		rsp, err := c.Send("GET", path, nil)
		if err != nil {
			return err
		}
		defer rsp.Body.Close()
		sc := bufio.NewScanner(rsp.Body)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			fmt.Fprintln(stdout, view.Entry(sc.Bytes()))
		}
		return sc.Err()
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// asker asks the operator, one answer a line, all from in: on a terminal after a prompt
// on out, from a pipe as the answers come. in is read byte by byte, never ahead, so
// that piped answers follow each other.
type asker struct {
	in  io.Reader
	out io.Writer
	p   *prompt.Prompter
}

func newAsker(in io.Reader, out io.Writer) *asker {
	p := prompt.New(in, out)
	p.SecretBuffer = func() []byte {
		b, _ := secret.LockedBuffer(vaultproto.MaxPepper) // the process is locked already
		return b
	}
	return &asker{in: in, out: out, p: p}
}

// line is an answer that is shown.
func (a *asker) line(text string) (string, error) {
	if f, ok := a.in.(*os.File); ok {
		if _, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err == nil {
			fmt.Fprint(a.out, text)
		}
	}
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := a.in.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			if len(b) < prompt.MaxLine {
				b = append(b, one[0])
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(b) > 0 {
				break
			}
			return "", fmt.Errorf("no answer: %w", err)
		}
	}
	return strings.TrimRight(string(b), "\r"), nil
}

// secret is an answer that is not shown, in a locked buffer: the caller wipes it.
func (a *asker) secret(text string) ([]byte, error) {
	return a.p.Password(text, "", nil)
}

// decideRequest approves or denies one request; an approval of a device enrolled with
// a pepper asks the pepper and sends it along, in a body built in a locked buffer: the
// pepper is never a string here.
func decideRequest(c *adminclient.Client, ask *asker, id string, approve bool) (server.RequestView, error) {
	var q server.RequestView
	path := "/v1/requests/" + url.PathEscape(id)
	if !approve {
		err := c.Do("POST", path+"/deny", struct{}{}, &q)
		return q, err
	}
	var list []server.RequestView
	if err := c.Do("GET", "/v1/requests", nil, &list); err != nil {
		return q, err
	}
	for _, r := range list {
		if r.ID != id || !r.Pepper {
			continue
		}
		p, err := ask.secret(fmt.Sprintf("Pepper for %s (%s):", r.Name, r.DeviceID))
		if err != nil {
			return q, err
		}
		defer secret.Wipe(p)
		if len(p) == 0 {
			return q, errors.New("this device was enrolled with a pepper: an approval without it is no approval")
		}
		const open, end = `{"pepper":`, `}`
		body, _ := secret.LockedBuffer(len(open) + secretjson.QuotedLen(p) + len(end))
		defer secret.Wipe(body)
		body = append(body, open...)
		if body, err = secretjson.AppendQuoted(body, p); err != nil {
			return q, err
		}
		body = append(body, end...)
		err = c.DoBody("POST", path+"/approve", bytes.NewReader(body), &q)
		return q, err
	}
	err := c.Do("POST", path+"/approve", struct{}{}, &q)
	return q, err
}

// answerQueue goes through the releases waiting for an operator, oldest
// first: approve, deny or skip each.
func answerQueue(c *adminclient.Client, ask *asker, stdout io.Writer) error {
	var list []server.RequestView
	if err := c.Do("GET", "/v1/requests", nil, &list); err != nil {
		return err
	}
	waiting := 0
	for _, r := range list {
		if r.State != "pending" {
			continue
		}
		waiting++
		pepper := ""
		if r.Pepper {
			pepper = ", with a pepper"
		}
		fmt.Fprintf(stdout, "Request %s: %s (%s), generation %d, from %s%s, until %s\n", r.ID, r.Name, r.DeviceID, r.Generation, r.Remote, pepper, r.Expires.Local().Format(time.TimeOnly))
		fmt.Fprintf(stdout, "  %s\n", view.Red(stdout, r.SecureBootRed, view.SecureBootLine(r.SecureBoot, nil)))
		for {
			a, err := ask.line("Approve, deny or skip? [a/d/s] ")
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(a)) {
			case "a", "approve":
				q, err := decideRequest(c, ask, r.ID, true)
				if err != nil {
					return err
				}
				fmt.Fprintf(stdout, "  %s; the machine is answered when it asks again.\n", q.State)
			case "d", "deny":
				q, err := decideRequest(c, ask, r.ID, false)
				if err != nil {
					return err
				}
				fmt.Fprintf(stdout, "  %s.\n", q.State)
			case "s", "skip", "":
				fmt.Fprintln(stdout, "  skipped.")
			default:
				continue
			}
			break
		}
	}
	if waiting == 0 {
		fmt.Fprintln(stdout, "No release waits for an operator.")
	}
	return nil
}
