package main

import (
	"bufio"
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

	"github.com/tpm2-trust/kira-vault/internal/adminclient"
	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
	"github.com/tpm2-trust/kira-vault/internal/view"
)

func cmdAdmin(cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	ask := asker(stdin, stderr)
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
	case "token":
		if err := want(1, "token create --name NAME [--mode auto|approve] [--ttl 1h] [--replace DEVICE]"); err != nil {
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

// asker reads the operator's answers, one line each, from in: on a
// terminal after a prompt on out - a secret without echo -, from a pipe as
// they come. One reader for all of them, so that piped answers follow each
// other.
func asker(in io.Reader, out io.Writer) func(prompt string, secret bool) (string, error) {
	br := bufio.NewReader(in)
	return func(prompt string, secret bool) (string, error) {
		if f, ok := in.(*os.File); ok {
			fd := int(f.Fd())
			if t, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil {
				fmt.Fprint(out, prompt)
				if secret {
					quiet := *t
					quiet.Lflag &^= unix.ECHO
					quiet.Lflag |= unix.ICANON | unix.ISIG
					if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
						return "", err
					}
					defer func() {
						unix.IoctlSetTermios(fd, unix.TCSETS, t)
						fmt.Fprintln(out)
					}()
				}
			}
		}
		line, err := br.ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && line != "") {
			return "", fmt.Errorf("no answer: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
}

// decideRequest approves or denies one request; an approval of a device
// enrolled with a pepper asks the pepper and sends it along.
func decideRequest(c *adminclient.Client, ask func(string, bool) (string, error), id string, approve bool) (server.RequestView, error) {
	var q server.RequestView
	if !approve {
		err := c.Do("POST", "/v1/requests/"+url.PathEscape(id)+"/deny", struct{}{}, &q)
		return q, err
	}
	var list []server.RequestView
	if err := c.Do("GET", "/v1/requests", nil, &list); err != nil {
		return q, err
	}
	var body any = struct{}{}
	for _, r := range list {
		if r.ID != id || !r.Pepper {
			continue
		}
		p, err := ask(fmt.Sprintf("Pepper for %s (%s): ", r.Name, r.DeviceID), true)
		if err != nil {
			return q, err
		}
		if p == "" {
			return q, errors.New("this device was enrolled with a pepper: an approval without it is no approval")
		}
		body = server.ApproveRequest{Pepper: &p}
	}
	err := c.Do("POST", "/v1/requests/"+url.PathEscape(id)+"/approve", body, &q)
	return q, err
}

// answerQueue goes through the releases waiting for an operator, oldest
// first: approve, deny or skip each.
func answerQueue(c *adminclient.Client, ask func(string, bool) (string, error), stdout io.Writer) error {
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
			a, err := ask("Approve, deny or skip? [a/d/s] ", false)
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
