package jsoncheck

import (
	"fmt"
	"strings"
	"testing"
)

func TestUniqueFieldSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, data     string
		exact, control bool
	}{
		{"object", `{"schema_version":1,"items":[{"id":"a"}]}`, true, true},
		{"duplicate", `{"id":1,"id":2}`, false, false},
		{"escaped duplicate", `{"id":1,"\u0069d":2}`, false, false},
		{"nested duplicate", `{"a":[{"id":1,"id":2}]}`, false, false},
		{"case alias", `{"ID":1,"id":2}`, true, false},
		{"unicode alias", `{"ſchema_version":1}`, true, false},
		{"empty key", `{"":1}`, true, false},
		{"independent objects", `[{"id":1},{"id":2}]`, true, true},
		{"trailing", `{} {}`, false, false},
		{"truncated", `{"id":`, false, false},
		{"empty", ``, false, false},
		{"scalar", `null`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if UniqueFields([]byte(tc.data)) != tc.exact || UniqueControlFields([]byte(tc.data)) != tc.control {
				t.Fatal("incorrect field semantics")
			}
		})
	}
	if UniqueControlFields([]byte(`{"` + strings.Repeat("a", 129) + `":1}`)) {
		t.Fatal("unbounded field name")
	}
	if UniqueFields([]byte(strings.Repeat("[", 26) + `0` + strings.Repeat("]", 26))) {
		t.Fatal("unbounded depth")
	}
	var keys []string
	for i := 0; i < 257; i++ {
		keys = append(keys, fmt.Sprintf(`"field_%d":0`, i))
	}
	data := []byte(`{` + strings.Join(keys, ",") + `}`)
	if !UniqueFields(data) || UniqueControlFields(data) {
		t.Fatal("control field count")
	}
}
