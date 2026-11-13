package previewruntime

import "encoding/json"

func marshal(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		return nil
	}
	return append(b, '\n')
}
