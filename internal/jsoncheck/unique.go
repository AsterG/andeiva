// Package jsoncheck provides side-effect-free checks for bounded JSON documents.
package jsoncheck

import (
	"bytes"
	"encoding/json"
	"io"
)

// UniqueFields retains exact JSON member-name semantics for existing protocols.
func UniqueFields(data []byte) bool { return unique(data, false) }

// UniqueControlFields also requires lower-case ASCII control names. This avoids
// aliases accepted by encoding/json's case-insensitive struct field matching.
// It is unsuitable for objects whose member names contain arbitrary user data.
func UniqueControlFields(data []byte) bool { return unique(data, true) }

func unique(data []byte, control bool) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 24 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delim, container := token.(json.Delim)
		if !container {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] || (control && (!controlName(name) || len(seen) >= 256)) || !walk(depth+1) {
					return false
				}
				seen[name] = true
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !walk(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func controlName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
			return false
		}
	}
	return true
}
