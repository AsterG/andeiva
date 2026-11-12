//go:build !linux

package authobservations

import (
	"context"
	"os"
)

func Prepare(*os.Root, string, string, string, AdmissionGuard) error   { return ErrUnavailable }
func Open(*os.Root, AdmissionGuard) (*Store, error)                    { return nil, ErrUnavailable }
func OpenDegraded(*os.Root, Selection, AdmissionGuard) (*Store, error) { return nil, ErrUnavailable }
func (*Store) publish(context.Context, snapshot) (uint64, bool, error) {
	return 0, false, ErrUnavailable
}
