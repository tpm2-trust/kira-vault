package server

import (
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/tpm2-trust/kira/core/vaultproto"

	"github.com/tpm2-trust/kira-vault/internal/keys"
	"github.com/tpm2-trust/kira-vault/internal/state"
)

// KeysStatus is the vault's keys as serve sees them now.
type KeysStatus struct {
	ApprovalDue  bool       `json:"approval_due"`
	Moved        []uint8    `json:"moved,omitempty"`    // the PCRs that moved since the newest approval
	Approved     *time.Time `json:"approved,omitempty"` // the approval in use
	Counter      uint64     `json:"counter"`
	ApprovalKeys []string   `json:"approval_keys"` // their kinds, in their order
	TPM          *keys.Info `json:"tpm,omitempty"`
	Error        string     `json:"error,omitempty"` // what could not be read
}

// StatusView is GET /v1/status: what control and 'status' show of a running vault.
type StatusView struct {
	Version        string      `json:"version"`
	StartedAt      time.Time   `json:"started_at"`
	URL            string      `json:"url"`
	Listen         string      `json:"listen"`
	OperatorListen string      `json:"operator_listen,omitempty"`
	OperatorURL    string      `json:"operator_url,omitempty"`
	Pin            string      `json:"pin"`
	PCRs           []uint8     `json:"pcrs"`
	TPMPath        string      `json:"tpm_path"`
	LeafNotAfter   time.Time   `json:"leaf_not_after"`
	RootNotAfter   time.Time   `json:"root_not_after"`
	Keys           *KeysStatus `json:"keys"`

	Devices          int `json:"devices"`
	Revoked          int `json:"revoked"`
	Locked           int `json:"locked"`
	NotSecureBoot    int `json:"not_secure_boot"` // whose last verified boot was not Secure Boot on
	Tokens           int `json:"tokens"`
	ExpiredTokens    int `json:"expired_tokens"`
	Operators        int `json:"operators"`
	PendingRequests  int `json:"pending_requests"`
	ShownKeyboards   int `json:"shown_keyboards"`
	ChallengesActive int `json:"challenges_active"`
}

// TokenView is one unused token of GET /v1/tokens: never its value, which is not
// kept; ID is the first 16 hex digits of its hash, for withdraw.
type TokenView struct {
	ID      string                 `json:"id"`
	Name    string                 `json:"name"`
	Mode    vaultproto.ReleaseMode `json:"mode"`
	Expires time.Time              `json:"expires"`
	Expired bool                   `json:"expired"`
	Replace string                 `json:"replace,omitempty"` // the device it enrols again
}

func tokenID(hash []byte) string { return hex.EncodeToString(hash)[:16] }

func (s *Server) adminStatus(w http.ResponseWriter, r *http.Request) {
	v, err := s.status()
	s.answer(w, v, err)
}

func (s *Server) status() (*StatusView, error) {
	devices, err := s.dir.Devices()
	if err != nil {
		return nil, err
	}
	tokens, err := s.dir.Tokens()
	if err != nil {
		return nil, err
	}
	ops, err := s.dir.Operators()
	if err != nil {
		return nil, err
	}
	v := &StatusView{
		Version: s.info.Version, StartedAt: s.info.StartedAt, URL: s.cfg.URL, Listen: s.cfg.Listen,
		OperatorListen: s.cfg.OperatorListen, OperatorURL: OperatorURL(s.cfg), Pin: s.pin, PCRs: s.cfg.PCRs,
		TPMPath: s.cfg.TPM,
		Devices: len(devices), Tokens: len(tokens), Operators: len(ops),
	}
	for _, d := range devices {
		switch {
		case d.Revoked:
			v.Revoked++
		case d.Locked:
			v.Locked++
		}
		if !d.Revoked && d.SecureBoot != nil && d.SecureBoot.Red() {
			v.NotSecureBoot++
		}
	}
	now := s.now()
	for _, t := range tokens {
		if !now.Before(t.Expires) {
			v.ExpiredTokens++
		}
	}
	s.mu.Lock()
	for _, q := range s.requests {
		switch q.state {
		case pending:
			v.PendingRequests++
		case fresh:
			v.ChallengesActive++
		}
	}
	v.ShownKeyboards = len(s.layouts)
	s.mu.Unlock()
	if c := s.info.Certs; c != nil {
		if l := c.Leaf(); l != nil {
			v.LeafNotAfter = l.NotAfter
		}
		if r := c.Root(); r != nil {
			v.RootNotAfter = r.NotAfter
		}
	}
	if s.info.Keys != nil {
		v.Keys = s.info.Keys()
	}
	return v, nil
}

func (s *Server) adminTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.dir.Tokens()
	if err != nil {
		s.answer(w, nil, err)
		return
	}
	now := s.now()
	views := []TokenView{}
	for _, t := range tokens {
		v := TokenView{ID: tokenID(t.Hash), Name: t.Name, Mode: t.Mode, Expires: t.Expires, Expired: !now.Before(t.Expires)}
		if t.Replace != nil {
			v.Replace = hex.EncodeToString(t.Replace)
		}
		views = append(views, v)
	}
	s.answer(w, views, nil)
}

// adminTokenWithdraw removes an unused token by its ID (or a longer prefix of its
// hash): it enrols nothing any more.
func (s *Server) adminTokenWithdraw(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(r.PathValue("id"))
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens, err := s.dir.Tokens()
	if err != nil {
		s.answer(w, nil, err)
		return
	}
	var found []state.StoredToken
	for _, t := range tokens {
		if len(id) >= 16 && strings.HasPrefix(hex.EncodeToString(t.Hash), id) {
			found = append(found, t)
		}
	}
	if len(found) != 1 {
		s.answer(w, nil, fail(http.StatusNotFound, "no unused token %q (kira-vault token list)", id))
		return
	}
	t := found[0]
	if err := s.dir.ConsumeToken(t.Hash); err != nil {
		s.answer(w, nil, err)
		return
	}
	if err := s.logAudit(state.Entry{Event: "token-withdraw", Name: t.Name, Actor: actorOf(r), Result: "done", Detail: "token " + tokenID(t.Hash)}); err != nil {
		s.answer(w, nil, err)
		return
	}
	s.answer(w, TokenView{ID: tokenID(t.Hash), Name: t.Name, Mode: t.Mode, Expires: t.Expires}, nil)
}

// Certs are the vault's certificates now: the leaf is renewed while serve runs.
type Certs interface {
	Leaf() *x509.Certificate
	Root() *x509.Certificate
}

// Info is what serve knows of itself that the configuration does not say.
type Info struct {
	Version   string
	StartedAt time.Time
	Certs     Certs              // nil: not shown
	Keys      func() *KeysStatus // the keys now; nil: not shown
}
