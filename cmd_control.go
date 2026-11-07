package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tpm2-trust/kira-vault/internal/control"
	"github.com/tpm2-trust/kira-vault/internal/state"
)

// controlEnv is where control reads; tests replace it.
var controlEnv = &control.HostEnv

func cmdControl(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("control", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", state.DefaultDir, "state directory")
	socket := fs.String("socket", "", "the admin socket (default: the configuration's)")
	lines := fs.Bool("lines", false, "line menus, not the full screen")
	debug := fs.Bool("debug", false, "say what is run")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("control takes no arguments, got %q", pos)
	}
	o := control.Options{Dir: *dir, Socket: *socket, Lines: *lines, Debug: *debug, CLI: run, Out: stdout, Env: controlEnv, AllowUser: controlAllowUser}
	if f, ok := stdin.(*os.File); ok {
		o.In = f
	} else {
		// No terminal: the input is none (an empty pipe), and control prints.
		r, w, err := os.Pipe()
		if err != nil {
			return err
		}
		w.Close()
		defer r.Close()
		o.In = r
	}
	return control.Run(o)
}

// controlAllowUser lets the tests run control as a user.
var controlAllowUser = false
