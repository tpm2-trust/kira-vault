package control

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// How serve runs, as the panel tells it from the admin socket's peer.
const (
	Stopped   = "stopped"   // nothing answers the admin socket
	Unit      = "unit"      // serve runs under kira-vault.service
	Container = "container" // serve runs in a container (podman, docker)
	Elsewhere = "elsewhere" // serve runs, neither under the unit nor in a container
)

// Deployment is how serve runs, and what is installed to run it.
type Deployment struct {
	Kind      string
	Pid       int    // serve's, in this namespace
	Engine    string // podman or docker, for Container
	Detail    string // what the decision rests on
	Unit      bool   // kira-vault.service is installed
	Quadlet   bool   // kira-vault.container is installed (podman's systemd generator)
	EngineBin string // the container engine on this host, if any
}

// UnitPaths and QuadletPaths are where the unit and the Quadlet are looked for.
var (
	UnitPaths    = []string{"/etc/systemd/system/kira-vault.service", "/usr/lib/systemd/system/kira-vault.service", "/lib/systemd/system/kira-vault.service"}
	QuadletPaths = []string{"/etc/containers/systemd/kira-vault.container", "/usr/share/containers/systemd/kira-vault.container"}
)

// peerPid is the pid of the process that answers the Unix socket at path
// (SO_PEERCRED): serve's, in this pid namespace (0 when it is outside it).
func peerPid(path string) (int, error) {
	c, err := net.Dial("unix", path)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return int(cred.Pid), nil
}

// deployment tells how serve runs: by its cgroup (the unit's, or a container
// engine's scope) and its user namespace (another than ours: a container).
func (e *Env) deployment(socket string) Deployment {
	d := Deployment{Kind: Stopped}
	for _, p := range e.UnitPaths {
		if _, err := os.Stat(p); err == nil {
			d.Unit = true
		}
	}
	for _, p := range e.QuadletPaths {
		if _, err := os.Stat(p); err == nil {
			d.Quadlet = true
		}
	}
	for _, bin := range []string{"podman", "docker"} {
		if p, err := e.LookPath(bin); err == nil {
			d.EngineBin = p
			break
		}
	}
	pid, err := e.PeerPid(socket)
	if err != nil {
		d.Detail = "nothing answers " + socket
		return d
	}
	d.Pid = pid
	if pid == 0 {
		d.Kind, d.Detail = Container, "serve answers from another pid namespace"
		return d
	}
	// control in serve's own container (podman exec, docker exec): its marks.
	for engine, mark := range map[string]string{"podman": "/run/.containerenv", "docker": "/.dockerenv"} {
		if _, err := os.Stat(filepath.Join(e.Root, mark)); err == nil {
			d.Kind, d.Engine, d.Detail = Container, engine, "control runs in serve's container"
			return d
		}
	}
	cg, _ := os.ReadFile(filepath.Join(e.Proc, fmt.Sprint(pid), "cgroup"))
	switch {
	case bytes.Contains(cg, []byte("/kira-vault.service")):
		d.Kind, d.Detail = Unit, "its cgroup is kira-vault.service's"
		return d
	case bytes.Contains(cg, []byte("libpod-")):
		d.Kind, d.Engine, d.Detail = Container, "podman", "its cgroup is a podman container's"
		return d
	case bytes.Contains(cg, []byte("docker-")) || bytes.Contains(cg, []byte("/docker/")):
		d.Kind, d.Engine, d.Detail = Container, "docker", "its cgroup is a docker container's"
		return d
	}
	ours, _ := os.Readlink(filepath.Join(e.Proc, "self", "ns", "user"))
	theirs, _ := os.Readlink(filepath.Join(e.Proc, fmt.Sprint(pid), "ns", "user"))
	if ours != "" && theirs != "" && ours != theirs {
		d.Kind, d.Detail = Container, "it runs in another user namespace"
		return d
	}
	d.Kind, d.Detail = Elsewhere, "pid "+fmt.Sprint(pid)+": "+strings.TrimSpace(firstLine(cg))
	return d
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\n")
	return s
}
