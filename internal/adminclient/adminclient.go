// Package adminclient talks to serve over its admin socket: the CLI's and control's
// way to the running vault.
package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/tpm2-trust/kira/core/vaultproto"
)

// Client is serve's admin interface on a Unix socket.
type Client struct {
	socket string
	http   *http.Client
}

// New is a client of the admin socket at socket.
func New(socket string) *Client {
	return &Client{socket: socket, http: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}}
}

// Socket is the socket's path.
func (c *Client) Socket() string { return c.socket }

// Send sends in (JSON, when not nil) and returns the answer of a 2xx status; any
// other status is the error the vault sent. The caller closes the body.
func (c *Client) Send(method, path string, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	return c.SendBody(method, path, body)
}

// SendBody is Send with a body made by the caller (nil for none): a body that holds a
// secret is built into the caller's buffer, which the caller wipes.
func (c *Client) SendBody(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://vault"+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rsp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("the vault's admin socket %s does not answer (is kira-vault serve running?): %w", c.socket, err)
	}
	if rsp.StatusCode/100 != 2 {
		defer rsp.Body.Close()
		var e vaultproto.ErrorResponse
		b, _ := io.ReadAll(rsp.Body)
		if json.Unmarshal(b, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(b))
		}
		return nil, fmt.Errorf("%s", e.Error)
	}
	return rsp, nil
}

// Do is Send, its answer decoded into out (when not nil).
func (c *Client) Do(method, path string, in, out any) error {
	rsp, err := c.Send(method, path, in)
	if err != nil {
		return err
	}
	return decode(rsp, out)
}

// DoBody is SendBody, its answer decoded into out (when not nil).
func (c *Client) DoBody(method, path string, body io.Reader, out any) error {
	rsp, err := c.SendBody(method, path, body)
	if err != nil {
		return err
	}
	return decode(rsp, out)
}

func decode(rsp *http.Response, out any) error {
	defer rsp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(rsp.Body).Decode(out)
}
