//go:build linux

package localruntime

import "time"

type resetCause struct {
	Role   string
	Reason string
	At     time.Time
}

// Diagnostic output contains only fixed categories, never child error text,
// authentication data, request bodies, or privileged command output.
func validResetCause(role, reason string) bool {
	if role == "supervisor" {
		return reason == "operator_reset"
	}
	if role != "api" && role != "helper" {
		return false
	}
	switch reason {
	case "process_exit", "invalid_event", "event_stream_error", "event_stream_closed":
		return true
	case "guardian_blocked":
		return role == "helper"
	case "recovery_server_exit", "listener_worker_exit", "audit_unavailable", "observation_unavailable", "coordinator_unavailable":
		return role == "api"
	}
	return false
}

func (i *instance) noteFailure(role, reason string) {
	if !validResetCause(role, reason) {
		return
	}
	i.failureMu.Lock()
	defer i.failureMu.Unlock()
	if i.failure.Reason == "" {
		i.failure = resetCause{role, reason, time.Now().UTC()}
	}
}

func (i *instance) resetCause() resetCause {
	i.failureMu.Lock()
	defer i.failureMu.Unlock()
	return i.failure
}
