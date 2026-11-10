//go:build !linux

package previewnet

import "context"

func Run(context.Context, Options) error { return ErrRuntime }
func ReadMetadata() (Metadata, error)    { return Metadata{}, ErrRuntime }
func Request(context.Context, ControlRequest) (ControlReply, error) {
	return ControlReply{}, ErrRuntime
}
