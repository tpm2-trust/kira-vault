package server_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-kira-vault/internal/server"
	"github.com/tpm2-trust/tpm2-kira-vault/internal/vaulttest"
	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/vaultproto"
)

// keyboardMachine is a machine enrolled with a pepper typed through the vault's keyboard, on a
// Secure Boot boot.
func (e *env) keyboardMachine(mode vaultproto.ReleaseMode) *vaulttest.Machine {
	e.t.Helper()
	m, err := vaulttest.NewMachine("db-03")
	if err != nil {
		e.t.Fatal(err)
	}
	m.Keyboard = true
	if _, err := m.Enrol(e.client, e.token(server.TokenRequest{Name: "db-03", Mode: mode})); err != nil {
		e.t.Fatalf("enrol: %v", err)
	}
	m.TPM.SetSecureBoot(attest.SecureBootOn)
	m.Approve()
	return m
}

// openLayout is what the machine makes of a release: the TPM opens the seed, the seed the layout.
func (e *env) openLayout(m *vaulttest.Machine, res *vaultproto.ReleaseResponse) *attest.KeyboardLayout {
	e.t.Helper()
	if res.Status != vaultproto.StatusReleased || res.Keyboard == nil || res.Remote == nil {
		e.t.Fatalf("%+v", res)
	}
	name, err := attest.ReleaseKeyName(m.RKPublic, m.SigningPublic(), m.PolicyRef)
	if err != nil {
		e.t.Fatal(err)
	}
	seed, err := m.TPM.ActivateCredentialFor(name, res.Keyboard.Credential, res.Keyboard.EncryptedSecret)
	if err != nil {
		e.t.Fatal(err)
	}
	l, err := attest.KeyboardLayoutOf(seed)
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

func (e *env) shownLayout(id string) *server.RequestView {
	e.t.Helper()
	var list []server.RequestView
	if code, msg := e.adminDo("GET", "/v1/requests", nil, &list); code != 200 {
		e.t.Fatalf("%d %s", code, msg)
	}
	for _, q := range list {
		if q.ID == id && q.Layout != "" {
			return &q
		}
	}
	return nil
}

// A release carries R and the seed; the layout the vault shows is the one the TPM's seed makes, for
// a while, never in the audit, and every boot another one.
func TestKeyboardRelease(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeAuto)
	if !e.deviceView(m).Keyboard {
		t.Fatal("the device view says no keyboard")
	}
	var layouts []string
	for boot := 0; boot < 2; boot++ {
		req, res, err := m.Release(e.client)
		if err != nil {
			t.Fatal(err)
		}
		l := e.openLayout(m, res)
		if r, err := m.Open(res.Remote); err != nil || !bytes.Equal(r, m.R) {
			t.Fatalf("R: %v", err)
		}
		v := e.shownLayout(req.RequestID)
		if v == nil || v.Layout != l.String() || v.KeyboardKeys != attest.KeyboardKeys || v.State != "released" || v.Name != "db-03" {
			t.Fatalf("shown %+v, the TPM's %s", v, l)
		}
		layouts = append(layouts, v.Layout)
		lines, _ := json.Marshal(e.auditLines())
		if strings.Contains(string(lines), v.Layout) {
			t.Fatalf("the audit holds the layout: %s", lines)
		}
		if !strings.Contains(string(lines), "one-time keyboard") {
			t.Fatalf("the audit says nothing of the keyboard: %s", lines)
		}
	}
	if layouts[0] == layouts[1] {
		t.Fatal("the same layout twice")
	}
	e.clock.Advance(server.LayoutTTL)
	var list []server.RequestView
	e.adminDo("GET", "/v1/requests", nil, &list)
	for _, q := range list {
		if q.Layout != "" {
			t.Fatalf("a layout past its time: %+v", q)
		}
	}
}

// Without a keyboard no seed; approve mode releases, and shows, only after the approval.
func TestKeyboardOnlyWithIt(t *testing.T) {
	e := newEnv(t)
	plain := e.machine(vaultproto.ModeAuto)
	plain.TPM.SetSecureBoot(attest.SecureBootOn)
	plain.Approve()
	if res := e.release(plain); res.Keyboard != nil {
		t.Fatalf("a seed for a device without a keyboard: %+v", res)
	}

	e = newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeApprove)
	req := e.pendingRequest(m)
	if v := e.shownLayout(req.RequestID); v != nil {
		t.Fatalf("a layout before the approval: %+v", v)
	}
	if code, msg := e.adminDo("POST", "/v1/requests/"+req.RequestID+"/approve", nil, nil); code != 200 {
		t.Fatalf("%d %s", code, msg)
	}
	var res vaultproto.ReleaseResponse
	if err := e.client.Post(vaultproto.PathRelease, req, &res); err != nil {
		t.Fatal(err)
	}
	if l := e.openLayout(m, &res); e.shownLayout(req.RequestID).Layout != l.String() {
		t.Fatal("the layout shown is not the TPM's")
	}
}

// No layout for a boot the vault refuses; a keyboard and an operator's pepper are not enrolled
// together.
func TestKeyboardRefusals(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeAuto)
	m.TPM.SetSecureBoot(attest.SecureBootOff)
	m.Approve()
	req, res, err := m.Release(e.client)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != vaultproto.StatusDenied || res.Keyboard != nil || e.shownLayout(req.RequestID) != nil {
		t.Fatalf("%+v", res)
	}

	both, err := vaulttest.NewMachine("db-04")
	if err != nil {
		t.Fatal(err)
	}
	both.Keyboard, both.Pepper = true, true
	_, err = both.Enrol(e.client, e.token(server.TokenRequest{Name: "db-04"}))
	wantHTTP(t, err, 400, "not taken together")
}
