package networkplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStrictDocument(t *testing.T) {
	data, err := json.Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := Canonical(sample())
	if err != nil {
		t.Fatal(err)
	}
	actual, err := Decode(data)
	if err != nil || actual.Hash != expected.Hash {
		t.Fatal("roundtrip", err)
	}
	for name, input := range map[string][]byte{
		"duplicate":     []byte(strings.Replace(string(data), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		"case alias":    []byte(strings.Replace(string(data), `"schema_version"`, `"SCHEMA_VERSION"`, 1)),
		"unicode alias": []byte(strings.Replace(string(data), `"schema_version"`, `"ſchema_version"`, 1)),
		"unknown":       []byte(strings.Replace(string(data), `"schema_version":1`, `"schema_version":1,"observed_index":2`, 1)),
		"trailing":      append(append([]byte{}, data...), []byte(` {}`)...),
		"null":          []byte(`null`),
		"oversized":     []byte(strings.Repeat(" ", MaxDocumentBytes+1)),
		"truncated":     data[:len(data)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(input); err == nil {
				t.Fatal("accepted ambiguous document")
			}
		})
	}
}
