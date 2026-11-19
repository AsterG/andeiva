//go:build !linux

package previewruntime

import (
	"context"
	"os"
)

func EnsureRoutedDHCPSubnetIDsV1(context.Context, *os.File, *os.File, []RoutedDHCPSubnetBindingV1) ([]uint32, error) {
	return nil, ErrRoutedDHCPSubnetRegistryV1
}
