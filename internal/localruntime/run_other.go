//go:build !linux

package localruntime

import (
	"context"
	"io"
)

func Main(_ context.Context, _ []string, _ io.Writer, diagnostic io.Writer) int {
	_, _ = io.WriteString(diagnostic, ErrUnavailable.Error()+"\n")
	return 1
}
