package server_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tpm2-trust/tpm2-kira-vault/internal/server"
	"github.com/tpm2-trust/tpm2-kira-vault/internal/vaulttest"
	"github.com/tpm2-trust/tpm2-kira/core/attest"
	"github.com/tpm2-trust/tpm2-kira/core/vaultproto"
)

var keyboardSalt = []byte("abcd2345")

// keyboardMachine is a machine enrolled with a salt typed through a keyboard, on a Secure Boot boot.
func (e *env) keyboardMachine(mode vaultproto.ReleaseMode, pepper bool) *vaulttest.Machine {
	e.t.Helper()
	m, err := vaulttest.NewMachine("db-03")
	if err != nil {
		e.t.Fatal(err)
	}
	m.KeyboardSalt, m.Pepper = keyboardSalt, pepper
	if _, err := m.Enrol(e.client, e.token(server.TokenRequest{Name: "db-03", Mode: mode})); err != nil {
		e.t.Fatalf("enrol: %v", err)
	}
	m.TPM.SetSecureBoot(attest.SecureBootOn)
	m.Approve()
	return m
}

// typedAt is what the machine holds after the vault's answer: the TPM opens K, K the pad.
type typedAt struct {
	id  string
	key []byte
	pad []byte
}

func (e *env) openKeyboard(m *vaulttest.Machine, req *vaultproto.ReleaseRequest, res *vaultproto.ReleaseResponse) *typedAt {
	e.t.Helper()
	if res.Status != vaultproto.StatusKeyboard || res.Keyboard == nil || res.Remote != nil {
		e.t.Fatalf("%+v", res)
	}
	name, err := attest.ReleaseKeyName(m.RKPublic, m.SigningPublic(), m.PolicyRef)
	if err != nil {
		e.t.Fatal(err)
	}
	k, err := m.TPM.ActivateCredentialFor(name, res.Keyboard.Key.Credential, res.Keyboard.Key.EncryptedSecret)
	if err != nil {
		e.t.Fatal(err)
	}
	pad, err := vaultproto.OpenKeyboardPad(k, m.DeviceID, res.Keyboard)
	if err != nil {
		e.t.Fatal(err)
	}
	return &typedAt{id: req.RequestID, key: k, pad: pad}
}

func (e *env) shownKeys(id string) string {
	e.t.Helper()
	var list []server.RequestView
	if code, msg := e.adminDo("GET", "/v1/requests", nil, &list); code != 200 {
		e.t.Fatalf("%d %s", code, msg)
	}
	for _, q := range list {
		if q.ID == id {
			return q.Keys
		}
	}
	return ""
}

func (e *env) prove(m *vaulttest.Machine, a *typedAt, keys []byte) *vaultproto.KeyboardResponse {
	e.t.Helper()
	var rsp vaultproto.KeyboardResponse
	if err := e.client.Post(vaultproto.PathKeyboard, vaultproto.KeyboardRequest{RequestID: a.id, DeviceID: m.DeviceID, Proof: vaultproto.KeyboardProof(a.key, a.id, keys)}, &rsp); err != nil {
		e.t.Fatal(err)
	}
	return &rsp
}

// The keys the vault shows and the pad the TPM opened make the salt; the right keys end it, and
// nothing of the salt, the keys or the pad reaches the audit.
func TestKeyboardRelease(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeAuto, false)
	req, res, err := m.Release(e.client)
	if err != nil {
		t.Fatal(err)
	}
	a := e.openKeyboard(m, req, res)
	keys := e.shownKeys(a.id)
	if len(keys) != len(keyboardSalt) {
		t.Fatalf("the keys shown: %q", keys)
	}
	got, err := attest.KeyboardSaltOf([]byte(keys), a.pad)
	if err != nil || !bytes.Equal(got, keyboardSalt) {
		t.Fatalf("keys %s make %s, %v", keys, got, err)
	}
	if e.device(m).LastRelease != nil {
		t.Fatal("released before the keys")
	}
	rsp := e.prove(m, a, []byte(keys))
	if rsp.Status != vaultproto.StatusReleased || len(rsp.Pepper) != 0 {
		t.Fatalf("%+v", rsp)
	}
	if e.device(m).LastRelease == nil {
		t.Fatal("no release noted")
	}
	if k := e.shownKeys(a.id); k != "" {
		t.Fatalf("the keys are still shown: %q", k)
	}
	// One proof: the request is gone.
	var again vaultproto.KeyboardResponse
	err = e.client.Post(vaultproto.PathKeyboard, vaultproto.KeyboardRequest{RequestID: a.id, DeviceID: m.DeviceID, Proof: vaultproto.KeyboardProof(a.key, a.id, []byte(keys))}, &again)
	wantHTTP(t, err, 404, "no keys were shown")

	lines, _ := json.Marshal(e.auditLines())
	for _, secret := range []string{string(keyboardSalt), keys} {
		if strings.Contains(string(lines), secret) {
			t.Fatalf("the audit holds %q: %s", secret, lines)
		}
	}
}

// Every boot other keys.
func TestKeyboardDiffersEveryBoot(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeAuto, false)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		req, res, err := m.Release(e.client)
		if err != nil {
			t.Fatal(err)
		}
		a := e.openKeyboard(m, req, res)
		keys := e.shownKeys(a.id)
		if seen[keys] {
			t.Fatalf("the same keys again: %s", keys)
		}
		seen[keys] = true
		if rsp := e.prove(m, a, []byte(keys)); rsp.Status != vaultproto.StatusReleased {
			t.Fatalf("%+v", rsp)
		}
	}
}

// Wrong keys are said, and the third ends the request. A proof without K is no proof.
func TestKeyboardWrongKeys(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeAuto, false)
	req, res, err := m.Release(e.client)
	if err != nil {
		t.Fatal(err)
	}
	a := e.openKeyboard(m, req, res)
	if rsp := e.prove(m, a, []byte("aaaaaaaa")); rsp.Status != vaultproto.StatusWrongKeys {
		t.Fatalf("%+v", rsp)
	}
	right := e.shownKeys(a.id)
	other := &typedAt{id: a.id, key: bytes.Repeat([]byte{9}, vaultproto.SecretSize)}
	if rsp := e.prove(m, other, []byte(right)); rsp.Status != vaultproto.StatusWrongKeys {
		t.Fatalf("the right keys without K: %+v", rsp)
	}
	if rsp := e.prove(m, a, []byte("bbbbbbbb")); rsp.Status != vaultproto.StatusDenied || !strings.Contains(rsp.Reason, "wrong 3 times") {
		t.Fatalf("%+v", rsp)
	}
	if e.device(m).LastRelease != nil {
		t.Fatal("released")
	}
}

// With a pepper: the keys first, then the operator, then the pepper, under K, since the TPM is
// closed by then. Before the keys nothing can be approved, and with wrong keys no pepper comes out.
func TestKeyboardPepperComesAfterTheKeys(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeApprove, true)
	req, res, err := m.Release(e.client)
	if err != nil {
		t.Fatal(err)
	}
	a := e.openKeyboard(m, req, res)
	keys := e.shownKeys(a.id)
	if code, _ := e.adminDo("POST", "/v1/requests/"+a.id+"/approve", map[string]any{"pepper": "secret"}, nil); code != 409 {
		t.Fatalf("approved before the keys: %d", code)
	}
	rsp := e.prove(m, a, []byte(keys))
	if rsp.Status != vaultproto.StatusPending {
		t.Fatalf("%+v", rsp)
	}
	if rsp := e.prove(m, a, []byte(keys)); rsp.Status != vaultproto.StatusPending {
		t.Fatalf("%+v", rsp)
	}
	if code, msg := e.adminDo("POST", "/v1/requests/"+a.id+"/approve", map[string]any{"pepper": "secret"}, nil); code != 200 {
		t.Fatalf("%d %s", code, msg)
	}
	if rsp := e.prove(m, a, []byte("aaaaaaaa")); rsp.Status != vaultproto.StatusWrongKeys || len(rsp.Pepper) != 0 {
		t.Fatalf("a pepper for wrong keys: %+v", rsp)
	}
	rsp = e.prove(m, a, []byte(keys))
	if rsp.Status != vaultproto.StatusReleased {
		t.Fatalf("%+v", rsp)
	}
	p, err := vaultproto.OpenKeyboardPepper(a.key, m.DeviceID, rsp.Pepper)
	if err != nil || string(p) != "secret" {
		t.Fatalf("%q, %v", p, err)
	}
}

// An operator's denial ends it, and a device in approve mode without a pepper is approved first.
func TestKeyboardApprovalAndDenial(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeApprove, false)
	ch, err := m.Challenge(e.client)
	if err != nil {
		t.Fatal(err)
	}
	req, err := m.ReleaseRequest(ch)
	if err != nil {
		t.Fatal(err)
	}
	send := func() *vaultproto.ReleaseResponse {
		var r vaultproto.ReleaseResponse
		if err := e.client.Post(vaultproto.PathRelease, req, &r); err != nil {
			t.Fatal(err)
		}
		return &r
	}
	if r := send(); r.Status != vaultproto.StatusPending {
		t.Fatalf("%+v", r)
	}
	if k := e.shownKeys(req.RequestID); k != "" {
		t.Fatalf("keys before the approval: %q", k)
	}
	if code, msg := e.adminDo("POST", "/v1/requests/"+req.RequestID+"/approve", nil, nil); code != 200 {
		t.Fatalf("%d %s", code, msg)
	}
	res := send()
	a := e.openKeyboard(m, req, res)
	// The answer lost on the way: the same keyboard again.
	if again := send(); !bytes.Equal(again.Keyboard.Ciphertext, res.Keyboard.Ciphertext) {
		t.Fatal("another keyboard for the same request")
	}
	if rsp := e.prove(m, a, []byte(e.shownKeys(a.id))); rsp.Status != vaultproto.StatusReleased {
		t.Fatalf("%+v", rsp)
	}
}

// No keys for a boot the vault would refuse, and none for a revoked device.
func TestKeyboardRefusals(t *testing.T) {
	e := newEnv(t)
	m := e.keyboardMachine(vaultproto.ModeAuto, false)
	m.TPM.SetSecureBoot(attest.SecureBootOff)
	m.Approve()
	req, res, err := m.Release(e.client)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, res, vaultproto.StatusDenied, "Secure Boot on")
	if k := e.shownKeys(req.RequestID); k != "" {
		t.Fatalf("keys for a boot without Secure Boot: %q", k)
	}

	m.TPM.SetSecureBoot(attest.SecureBootOn)
	m.Approve()
	req, res, err = m.Release(e.client)
	if err != nil {
		t.Fatal(err)
	}
	a := e.openKeyboard(m, req, res)
	keys := e.shownKeys(a.id)
	if code, msg := e.adminDo("POST", "/v1/devices/"+e.deviceView(m).ID+"/revoke", nil, nil); code != 200 {
		t.Fatalf("%d %s", code, msg)
	}
	if rsp := e.prove(m, a, []byte(keys)); rsp.Status != vaultproto.StatusDenied {
		t.Fatalf("a revoked device: %+v", rsp)
	}
}

// A bad salt never gets in.
func TestKeyboardEnrolRefusesABadSalt(t *testing.T) {
	e := newEnv(t)
	m, err := vaulttest.NewMachine("db-03")
	if err != nil {
		t.Fatal(err)
	}
	m.KeyboardSalt = []byte("short")
	_, err = m.Enrol(e.client, e.token(server.TokenRequest{Name: "db-03"}))
	var se *vaulttest.StatusError
	if !errors.As(err, &se) || se.Code != 400 {
		t.Fatalf("%v", err)
	}
}
