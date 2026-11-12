package previewnet

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
)

type fixtureFailure struct {
	check string
	cause error
}

func (e *fixtureFailure) Error() string { return ErrRuntime.Error() }
func (e *fixtureFailure) Unwrap() error { return e.cause }

// Only bounded machine categories enter the privileged lifecycle journal.
// Error text, command output and addresses never become diagnostic fields.
type lifecycleDiagnostic struct {
	Phase string `json:"phase"`
	Check string `json:"check"`
	Code  string `json:"code"`
}

func diagnosticFor(phase string, err error) lifecycleDiagnostic {
	switch phase {
	case "directories", "lock", "recovery", "boot_identity", "host_identity", "fixture_create", "listener_start", "initial_policy", "run_identity", "metadata", "namespace_pin", "control_socket", "initial_check", "readiness", "event_log", "control_accept", "control_request", "periodic_check", "cleanup":
	default:
		phase = "unknown"
	}
	d := lifecycleDiagnostic{Phase: phase, Check: "runtime", Code: "rejected"}
	var failure *fixtureFailure
	if errors.As(err, &failure) {
		switch failure.check {
		case "host", "sentinel", "listeners":
			d.Check = failure.check
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		d.Code = "deadline"
	case errors.Is(err, context.Canceled):
		d.Code = "canceled"
	case errors.Is(err, ErrRecovery):
		d.Code = "recovery_required"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		d.Code = "storage_capacity"
	case errors.Is(err, os.ErrPermission):
		d.Code = "permission"
	case errors.Is(err, os.ErrNotExist):
		d.Code = "missing"
	case failure != nil && failure.cause != nil && failure.check == "host" && strings.HasPrefix(failure.cause.Error(), "ANDEIVA_NFT_HOST_BASELINE_CHANGED:"):
		d.Code = "baseline_changed"
	}
	return d
}

type lifecycleFailures struct {
	emit                     func(string, lifecycleDiagnostic)
	primarySent, cleanupSent bool
	primaryData, cleanupData *lifecycleDiagnostic
	flushed                  bool
}

func (f *lifecycleFailures) primary(phase string, err error) {
	if f.primarySent {
		return
	}
	f.primarySent = true
	if err != nil {
		d := diagnosticFor(phase, err)
		f.primaryData = &d
	}
}

func (f *lifecycleFailures) cleanup(err error) {
	if err != nil && !f.cleanupSent {
		f.cleanupSent = true
		d := diagnosticFor("cleanup", err)
		f.cleanupData = &d
	}
}

func (f *lifecycleFailures) flush() {
	if f.flushed {
		return
	}
	f.flushed = true
	if f.primaryData != nil {
		f.emit("failure", *f.primaryData)
	}
	if f.cleanupData != nil {
		f.emit("cleanup_failure", *f.cleanupData)
	}
}

// Diagnostic I/O must never stand between a failed fixture and its cleanup.
func (f *lifecycleFailures) finish(phase string, primary error, cleanup func() error) (error, error) {
	f.primary(phase, primary)
	cleanupErr := cleanup()
	f.cleanup(cleanupErr)
	return errors.Join(primary, cleanupErr), cleanupErr
}

func checkRuntimeHealth(ctx context.Context, f fixture) error {
	if err := checkFixture(ctx, f); err != nil {
		return err
	}
	if err := f.CheckPreviewListeners(ctx); err != nil {
		return &fixtureFailure{check: "listeners", cause: err}
	}
	return nil
}
