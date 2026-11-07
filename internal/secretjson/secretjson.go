// Package secretjson carries a secret through JSON as bytes, never as a Go string: a
// string cannot be wiped and is copied wherever it goes. Bytes reads a JSON string
// into a buffer of its own; AppendQuoted writes bytes as a JSON string into the
// caller's buffer. Whoever holds the bytes wipes them (secret.Wipe).
package secretjson

import (
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

// Bytes is a JSON string read as bytes. As a field, take a *Bytes: absent stays nil.
type Bytes []byte

var errNotString = errors.New("not a JSON string")

// UnmarshalJSON reads a JSON string into new bytes, without a string between: the
// decoder's input is the caller's to wipe, the result the holder's.
func (b *Bytes) UnmarshalJSON(data []byte) error {
	out, err := Unquote(data)
	if err != nil {
		return err
	}
	*b = out
	return nil
}

// Unquote is the content of a JSON string literal (its quotes included in data), its
// escapes resolved, in new bytes. A literal that is not valid JSON or not valid UTF-8 is
// an error, and nothing of it is kept.
func Unquote(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return nil, errNotString
	}
	in := data[1 : len(data)-1]
	out := make([]byte, 0, len(in))
	fail := func(msg string) ([]byte, error) {
		clear(out[:cap(out)])
		return nil, errors.New(msg)
	}
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '"':
			return fail("an unescaped quote in a JSON string")
		case c < 0x20:
			return fail("a control character in a JSON string")
		case c != '\\':
			out = append(out, c)
			continue
		}
		i++
		if i == len(in) {
			return fail("a JSON string ends in a backslash")
		}
		switch in[i] {
		case '"', '\\', '/':
			out = append(out, in[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in[i+1:])
			if !ok {
				return fail("a bad \\u escape in a JSON string")
			}
			i += 4
			if utf16.IsSurrogate(r) {
				if i+2 < len(in) && in[i+1] == '\\' && in[i+2] == 'u' {
					if r2, ok := hex4(in[i+3:]); ok {
						if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
							r = dec
							i += 6
						}
					}
				}
				if utf16.IsSurrogate(r) { // alone: U+FFFD, as encoding/json reads it
					r = utf8.RuneError
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return fail("a bad escape in a JSON string")
		}
	}
	if !utf8.Valid(out) {
		return fail("a JSON string that is not UTF-8")
	}
	return out, nil
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(v)
	}
	return r, true
}

const hexDigits = "0123456789abcdef"

// AppendQuoted appends s as a JSON string literal to dst, which must have room
// (QuotedLen): an append that would grow it - and leave a copy behind - is refused.
func AppendQuoted(dst, s []byte) ([]byte, error) {
	if cap(dst)-len(dst) < QuotedLen(s) {
		return dst, errors.New("the buffer has no room for the quoted secret")
	}
	dst = append(dst, '"')
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c < 0x20 || c == 0x7f:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"'), nil
}

// QuotedLen is the length of s as a JSON string literal (AppendQuoted).
func QuotedLen(s []byte) int {
	n := 2
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			n += 2
		case c < 0x20 || c == 0x7f:
			n += 6
		default:
			n++
		}
	}
	return n
}
