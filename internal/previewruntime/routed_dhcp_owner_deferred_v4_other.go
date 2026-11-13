//go:build !linux

package previewruntime

import "context"

type RoutedDHCPDeferredOwnerV4 struct{}

func PrepareRoutedDHCPDeferredOwnerV4(context.Context, RoutedDHCPOwnerOptionsV3) (*RoutedDHCPDeferredOwnerV4, error) {
	return nil, ErrIdentity
}
func RunRoutedDHCPDeferredOwnerRoleV4(context.Context) error { return ErrIdentity }
func NewRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4, RoutedDHCPDeferredBindingV4) (*RoutedDHCPDeferredReaderV4, error) {
	return nil, ErrIdentity
}
func (*RoutedDHCPDeferredOwnerV4) TakeReaderFiles() (RoutedDHCPDeferredFilesV4, RoutedDHCPDeferredBindingV4, error) {
	return RoutedDHCPDeferredFilesV4{}, RoutedDHCPDeferredBindingV4{}, ErrIdentity
}
func (*RoutedDHCPDeferredOwnerV4) Activate(context.Context) error { return ErrIdentity }
func (*RoutedDHCPDeferredOwnerV4) Close() error                   { return nil }
func (*RoutedDHCPDeferredOwnerV4) Done() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}
