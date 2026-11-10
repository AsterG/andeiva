package localpolicy

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
)

var jsonField = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Struct decoding otherwise accepts duplicate and case-folded field names.
// Local service documents use one exact ASCII spelling for each JSON field.
func uniqueFields(data []byte) bool {
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
		delim, compound := token.(json.Delim)
		if !compound {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || !jsonField.MatchString(name) || seen[name] || !walk(depth+1) {
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
