package adminclient

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// A client of a socket: the answer decoded, the vault's error said as it is, a body of
// the caller's sent as it is, and a socket that does not answer named.
func TestClient(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ok", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"name":"vault"}`) })
	mux.HandleFunc("POST /v1/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "no type", 400)
			return
		}
		io.Copy(w, r.Body)
	})
	mux.HandleFunc("GET /v1/fail", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"error":"the device is revoked"}`)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	c := New(sock)
	var out struct{ Name string }
	if err := c.Do("GET", "/v1/ok", nil, &out); err != nil || out.Name != "vault" {
		t.Fatalf("ok: %+v %v", out, err)
	}
	if err := c.DoBody("POST", "/v1/echo", strings.NewReader(`{"name":"body"}`), &out); err != nil || out.Name != "body" {
		t.Fatalf("a body of the caller's: %+v %v", out, err)
	}
	if err := c.Do("GET", "/v1/fail", nil, nil); err == nil || err.Error() != "the device is revoked" {
		t.Fatalf("the vault's error: %v", err)
	}
	if err := New(filepath.Join(t.TempDir(), "none")).Do("GET", "/v1/ok", nil, nil); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("no socket: %v", err)
	}
}
