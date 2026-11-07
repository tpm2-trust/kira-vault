// Package control is the vault's control panel: what the vault host and its vault
// are now (the facts), the sections and steps that take a person from an empty host
// to a serving vault and through its daily work (the model), and the full screen, the
// line menus and the printout that show them. Every step runs a command of the
// vault's own CLI, which stays doable by hand.
//
// The panel never opens the TPM (serve has it) and never writes the state directory:
// it reads files, asks serve over the admin socket, and runs the CLI.
package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/tpm2-trust/go-uefi-slim/efivar"

	"github.com/tpm2-trust/kira-vault/internal/adminclient"
	"github.com/tpm2-trust/kira-vault/internal/bootstate"
	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/server"
	"github.com/tpm2-trust/kira-vault/internal/state"
)

// Env is where the panel reads: the host's, or a test's.
type Env struct {
	Root         string // the file system's root, where a container's marks are ("/")
	Proc         string // /proc
	EFIVars      string // efivarfs
	UnitPaths    []string
	QuadletPaths []string
	LookPath     func(string) (string, error)
	PeerPid      func(socket string) (int, error)
	Volume       func(dir string) (*bootstate.Volume, error)
	Resolve      func(host string) ([]string, error)
	LocalAddrs   func() ([]net.IP, error)
	Now          func() time.Time
}

// HostEnv is this host's.
var HostEnv = Env{
	Root: "/", Proc: "/proc", EFIVars: "/sys/firmware/efi/efivars", UnitPaths: UnitPaths, QuadletPaths: QuadletPaths,
	LookPath: exec.LookPath, PeerPid: peerPid, Volume: bootstate.VolumeOf, Resolve: net.LookupHost,
	LocalAddrs: func() ([]net.IP, error) {
		addrs, err := net.InterfaceAddrs()
		var out []net.IP
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, n.IP)
			}
		}
		return out, err
	},
	Now: time.Now,
}

// Facts is what the panel shows: the fast part at once, the slow part after
// (Checking until it came).
type Facts struct {
	Root bool

	Dir        string
	DirExists  bool
	DirMode    fs.FileMode
	Config     *state.Config
	ConfigErr  error
	Master     *state.Master
	MasterErr  error
	Approvals  []*keys.Approval
	Socket     string
	SocketMode fs.FileMode
	SocketUID  uint32
	SocketErr  error
	Deployment Deployment
	SecureBoot efivar.SecureBootState
	Volume     *bootstate.Volume
	VolumeErr  error
	LeafCert   *x509.Certificate
	RootCert   *x509.Certificate

	// The slow part.
	Checking  bool
	Status    *server.StatusView
	StatusErr error
	Devices   []server.DeviceView
	Requests  []server.RequestView
	Tokens    []server.TokenView
	Operators []server.OperatorView
	TLS       []TLSCheck
	DNS       *DNSCheck
}

// TLSCheck is a handshake to a listen address, verified against the vault's root and
// pin with the URL's host as the name.
type TLSCheck struct {
	Interface, Addr string
	Err             error
}

// DNSCheck is the URL's host: what it resolves to, and whether one of those is this
// host's (no: NAT, another machine, or the wrong name).
type DNSCheck struct {
	Host  string
	Addrs []string
	Local bool
	Err   error
}

// Initialised says the state directory holds a vault.
func (f *Facts) Initialised() bool { return f.Config != nil }

// Serving says serve answers the admin socket.
func (f *Facts) Serving() bool { return f.Deployment.Kind != Stopped }

// Fast reads what needs no network and no serve: the state directory, the socket,
// the deployment, the host's Secure Boot, the volume.
func (e *Env) Fast(dir, socket string) *Facts {
	f := &Facts{Root: os.Geteuid() == 0, Dir: dir, Checking: true}
	d := state.Dir{Path: dir}
	if st, err := os.Stat(dir); err == nil {
		f.DirExists, f.DirMode = true, st.Mode().Perm()
	}
	if d.Initialised() {
		f.Config, f.ConfigErr = d.Config()
		f.Master, f.MasterErr = d.Master()
		f.Approvals, _ = d.Approvals()
		if certs, err := readCerts(d); err == nil {
			f.LeafCert, f.RootCert = certs[0], certs[1]
		}
	}
	f.Socket = socket
	if socket == "" {
		f.Socket = state.DefaultAdminSocket
		if f.Config != nil {
			f.Socket = f.Config.AdminSocket
		}
	}
	if st, err := os.Stat(f.Socket); err != nil {
		f.SocketErr = err
	} else {
		f.SocketMode = st.Mode().Perm()
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			f.SocketUID = s.Uid
		}
	}
	f.Deployment = e.deployment(f.Socket)
	f.SecureBoot = efivar.Store{Dir: e.EFIVars}.SecureBootState()
	if f.DirExists {
		f.Volume, f.VolumeErr = e.Volume(dir)
	}
	return f
}

// readCerts reads the leaf and the root, never renewing them (tlsutil.Load would).
func readCerts(d state.Dir) ([2]*x509.Certificate, error) {
	var out [2]*x509.Certificate
	for i, p := range []string{d.TLSCertPath(), d.TLSRootPath()} {
		b, err := os.ReadFile(p)
		if err != nil {
			return out, err
		}
		c, err := parsePEM(b)
		if err != nil {
			return out, fmt.Errorf("%s: %w", p, err)
		}
		out[i] = c
	}
	return out, nil
}

// Slow asks serve and the network; f is the fast part, which it completes.
func (e *Env) Slow(f *Facts) {
	defer func() { f.Checking = false }()
	if f.Serving() {
		c := adminclient.New(f.Socket)
		var st server.StatusView
		if f.StatusErr = c.Do("GET", "/v1/status", nil, &st); f.StatusErr == nil {
			f.Status = &st
		}
		c.Do("GET", "/v1/devices", nil, &f.Devices)
		c.Do("GET", "/v1/requests", nil, &f.Requests)
		c.Do("GET", "/v1/tokens", nil, &f.Tokens)
		c.Do("GET", "/v1/operators", nil, &f.Operators)
	}
	if f.Config == nil {
		return
	}
	u, err := url.Parse(f.Config.URL)
	if err != nil {
		return
	}
	host := u.Hostname()
	dns := &DNSCheck{Host: host}
	if ip := net.ParseIP(host); ip != nil {
		dns.Addrs = []string{host}
	} else {
		dns.Addrs, dns.Err = e.Resolve(host)
	}
	if local, err := e.LocalAddrs(); err == nil {
		for _, a := range dns.Addrs {
			for _, l := range local {
				if ip := net.ParseIP(a); ip != nil && ip.Equal(l) {
					dns.Local = true
				}
			}
		}
	}
	f.DNS = dns
	if f.Serving() && f.RootCert != nil {
		checks := []TLSCheck{{Interface: "machines", Addr: f.Config.Listen}}
		if f.Config.OperatorListen != "" {
			checks = append(checks, TLSCheck{Interface: "operators", Addr: f.Config.OperatorListen})
		}
		for i := range checks {
			checks[i].Err = handshake(checks[i].Addr, host, f.RootCert)
		}
		f.TLS = checks
	}
}

// handshake connects to a listen address (on this host when it names no host) and
// verifies the vault there as a machine does: a chain to the vault's root (whose key
// the pin is), the URL's host as the name.
func handshake(listen, name string, root *x509.Certificate) error {
	h, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if h == "" || h == "0.0.0.0" || h == "::" {
		h = "127.0.0.1"
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort(h, port), &tls.Config{
		RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		return err
	}
	return conn.Close()
}

// parsePEM is the certificate of a PEM file.
func parsePEM(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}
