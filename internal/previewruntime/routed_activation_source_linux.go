//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const RoutedActivationSourceRoleV1 = "--andeiva-routed-activation-source-v1"
const activationSourceTimeoutV1 = 45 * time.Second

type activationSourceRequestV1 struct {
	Version    int                           `json:"version"`
	ParentPID  int                           `json:"parent_pid"`
	Identities Identities                    `json:"identities"`
	Expected   configpoc.LegacyFingerprintV2 `json:"expected"`
}

// RunRoutedActivationSourceRoleV1 borrows only the classic store. The root
// installer owns service exclusion, namespace checks and all publication.
func RunRoutedActivationSourceRoleV1(ctx context.Context) (result error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if checkMigrationWorkerFDsV3(2) != nil {
		return ErrIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, activationSourceTimeoutV1)
	defer cancel()
	control, err := migrationFingerprintControlV3(activationSourceTimeoutV1)
	if err != nil {
		return err
	}
	defer control.Close()
	input := bufio.NewReaderSize(control, 4096)
	raw, err := input.ReadSlice('\n')
	var req activationSourceRequestV1
	if err != nil || routedPrivateDecodeV4(raw, &req) != nil || req.Version != 1 ||
		authenticateMigrationFingerprintParentV3(req.ParentPID, req.Identities) != nil {
		return ErrIdentity
	}
	area, err := os.OpenRoot(DataDir + "/state")
	if err != nil {
		return ErrStorage
	}
	defer func() { result = errors.Join(result, area.Close()) }()
	return configpoc.WithLegacyFingerprintRecheckV3(ctx, area, "firewall", func(ctx context.Context, fp configpoc.LegacyFingerprintV2, recheck func() error) error {
		if fp != req.Expected {
			return ErrConfiguration
		}
		return exchangeActivationSourceProofV1(ctx, input, os.Stdout, recheck)
	})
}

func exchangeActivationSourceProofV1(ctx context.Context, input *bufio.Reader, output io.Writer, recheck func() error) error {
	if _, err := io.WriteString(output, "locked\n"); err != nil {
		return err
	}
	frame, err := input.ReadSlice('\n')
	if err != nil || string(frame) != "verify\n" || ctx.Err() != nil {
		return ErrUnavailable
	}
	if err = recheck(); err != nil {
		return err
	}
	if _, err = io.WriteString(output, "verified\n"); err != nil {
		return err
	}
	frame, err = input.ReadSlice('\n')
	if err != nil || string(frame) != "release\n" || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
