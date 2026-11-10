package adminapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

func (h *handler) deny(w http.ResponseWriter, r *http.Request, actor, action string, status int, code string) {
	if r.Method == http.MethodPost || actor != "unknown" {
		if err := h.options.Auth.RecordDenied(actor, action); err != nil {
			h.authError(w, err)
			return
		}
	}
	h.fail(w, status, code)
}

// Scan before struct decoding, which otherwise accepts repeated and case-folded keys.
func validateJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON depth")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				token, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok {
					return errors.New("JSON key")
				}
				for _, r := range key {
					if r > 127 {
						return errors.New("non-ASCII JSON key")
					}
				}
				key = strings.ToLower(key)
				if keys[key] {
					return errors.New("duplicate JSON key")
				}
				keys[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return errors.New("JSON object required")
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
