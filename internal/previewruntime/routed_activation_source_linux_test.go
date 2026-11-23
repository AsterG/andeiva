//go:build linux

package previewruntime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestActivationSourceProofRequiresRecheckAndRelease(t *testing.T) {
	conflict := errors.New("source changed")
	for _, tc := range []struct {
		name, input, output string
		recheck, result     error
	}{
		{"missing verify", "", "locked\n", nil, ErrUnavailable},
		{"out of order", "release\n", "locked\n", nil, ErrUnavailable},
		{"changed source", "verify\nrelease\n", "locked\n", conflict, conflict},
		{"lost installer after proof", "verify\n", "locked\nverified\n", nil, ErrUnavailable},
		{"verified release", "verify\nrelease\n", "locked\nverified\n", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := exchangeActivationSourceProofV1(context.Background(), bufio.NewReader(strings.NewReader(tc.input)), &output, func() error { return tc.recheck })
			if !errors.Is(err, tc.result) || output.String() != tc.output {
				t.Fatalf("result %v, frames %q", err, output.String())
			}
		})
	}
}
