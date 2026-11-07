package secretjson

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"testing"
)

// Unquote reads what encoding/json reads, byte for byte, and refuses what it refuses;
// AppendQuoted writes what encoding/json reads back as the same bytes.
func TestAgainstEncodingJSON(t *testing.T) {
	samples := []string{
		``, `a`, `pepper with spaces`, `"quoted"`, `back\slash`, "tab\there", "line\nfeed", "\x00\x01\x1f\x7f",
		`ünïcödé`, `日本語`, "emoji 😀", `</script>`, `\u0041`, "  ",
	}
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 500; i++ {
		b := make([]byte, r.IntN(40))
		for j := range b {
			b[j] = byte(r.IntN(128))
		}
		samples = append(samples, string(b))
	}
	for _, s := range samples {
		// What a client's JSON encoder sends, read back.
		enc, _ := json.Marshal(s)
		got, err := Unquote(enc)
		if err != nil || string(got) != s {
			t.Fatalf("Unquote(%s) = %q %v, want %q", enc, got, err, s)
		}
		// What AppendQuoted writes, read by encoding/json.
		buf := make([]byte, 0, QuotedLen([]byte(s)))
		q, err := AppendQuoted(buf, []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if len(q) != QuotedLen([]byte(s)) {
			t.Fatalf("QuotedLen(%q) = %d, wrote %d", s, QuotedLen([]byte(s)), len(q))
		}
		var back string
		if err := json.Unmarshal(q, &back); err != nil || back != s {
			t.Fatalf("AppendQuoted(%q) = %s: %q %v", s, q, back, err)
		}
	}
	// Escapes a client may send that encoding/json does not write.
	for lit, want := range map[string]string{`"\/"`: "/", `"\b\f"`: "\b\f", `"\ud83d\ude00"`: "\U0001F600", `"\u00e9"`: "\u00e9", `"\ud83d"`: "\uFFFD"} {
		if got, err := Unquote([]byte(lit)); err != nil || string(got) != want {
			t.Errorf("Unquote(%s) = %q %v", lit, got, err)
		}
	}
	for _, bad := range []string{`abc`, `"abc`, `"a"b"`, `"\x"`, `"\u12"`, "\"a\x01\"", `"\`} {
		var v string
		if json.Unmarshal([]byte(bad), &v) == nil {
			t.Fatalf("encoding/json takes %q: the test is wrong", bad)
		}
		if got, err := Unquote([]byte(bad)); err == nil {
			t.Errorf("Unquote(%q) = %q, want an error", bad, got)
		}
	} // Stricter than encoding/json, which reads invalid UTF-8 as U+FFFD: a secret is taken
	// as it was meant or not at all.
	if got, err := Unquote([]byte("\"\xff\"")); err == nil {
		t.Errorf("invalid UTF-8 taken: %q", got)
	}
}

// As a field: absent stays nil, present is bytes.
func TestField(t *testing.T) {
	var a struct {
		Pepper *Bytes `json:"pepper,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{}`), &a); err != nil || a.Pepper != nil {
		t.Fatalf("absent: %v %v", a.Pepper, err)
	}
	if err := json.Unmarshal([]byte(`{"pepper":"s\"ecret"}`), &a); err != nil || a.Pepper == nil || !bytes.Equal(*a.Pepper, []byte(`s"ecret`)) {
		t.Fatalf("present: %v %v", a.Pepper, err)
	}
	if err := json.Unmarshal([]byte(`{"pepper":7}`), &a); err == nil {
		t.Fatal("a number taken as a pepper")
	}
}

// A buffer without room is refused, not grown.
func TestAppendQuotedNoRoom(t *testing.T) {
	buf := make([]byte, 0, 4)
	if _, err := AppendQuoted(buf, []byte("abcd")); err == nil {
		t.Fatal("grown past its capacity")
	}
}
