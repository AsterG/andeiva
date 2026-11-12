//go:build !linux

package networkexecutor

import (
	"context"
	"os"
)

// New refuses unsupported platforms without opening paths or running commands.
func New(context.Context, *os.File) (*Executor, error) { return nil, ErrUnsupported }

// NewWithHost refuses unsupported platforms without inspecting descriptors.
func NewWithHost(context.Context, *os.File, *os.File) (*Executor, error) { return nil, ErrUnsupported }
