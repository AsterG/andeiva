//go:build !linux

package previewruntime

import "context"

type RoutedDHCPOwnerV3 struct{}

func StartRoutedDHCPOwnerV3(context.Context, RoutedDHCPOwnerOptionsV3) (*RoutedDHCPOwnerV3, error) {
	return nil, ErrIdentity
}
func RunRoutedDHCPOwnerRoleV3(context.Context) error { return ErrIdentity }
func NewRoutedDHCPOwnerReaderV3(RoutedDHCPOwnerFilesV3, RoutedDHCPOwnerBindingV3) (*RoutedDHCPOwnerReaderV3, error) {
	return nil, ErrIdentity
}
func (*RoutedDHCPOwnerV3) TakeReaderFiles() (RoutedDHCPOwnerFilesV3, RoutedDHCPOwnerBindingV3, error) {
	return RoutedDHCPOwnerFilesV3{}, RoutedDHCPOwnerBindingV3{}, ErrIdentity
}
func (*RoutedDHCPOwnerV3) Close() error          { return nil }
func (*RoutedDHCPOwnerV3) Done() <-chan struct{} { c := make(chan struct{}); close(c); return c }
