//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"golang.org/x/sys/unix"
)

func TestNativeRoutedDHCPRetainedRulesV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, "rules")
}

func nativeDHCPRulesRootV4(t *testing.T, ctx context.Context, ns [3]*os.File, supervisor *RoutedLaunchSupervisorV3, logs *nativeLogV3, bound nativeDHCPJobsReportV4) {
	t.Helper()
	defer func() {
		if t.Failed() {
			for _, line := range strings.Split(logs.String(), "\n") {
				if strings.HasPrefix(line, "ANDEIVA_NATIVE_DHCP_FIRST_FAILURE_V4 ") ||
					strings.HasPrefix(line, "ANDEIVA_NATIVE_LEASE_SPAN_V4 ") && strings.Contains(line, `"phase":"rule_hold_`) {
					t.Log(line)
				}
			}
		}
	}()
	nativeDHCPContinuitySourceV4(t, ctx, ns[1])
	flow, err := startNativeDHCPContinuityV4(t, ctx, ns[1], ns[2])
	if err != nil {
		t.Fatal(err)
	}
	supervisor.mu.Lock()
	err = supervisor.api.cmd.Process.Signal(syscall.SIGUSR2)
	supervisor.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"rules-confirmed", "rules-reverted"} {
		report := nativeDHCPJobsWaitReportV4(t, ctx, logs, phase)
		if !reflect.DeepEqual(report.Grant, bound.Grant) || report.Running == bound.Running {
			t.Fatalf("%s did not preserve the original WAN grant and select the expected firewall lineage", phase)
		}
		sysctl := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", "/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward")
		sysctl.ExtraFiles = []*os.File{ns[0]}
		sysctl.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		output, err := sysctl.Output()
		if err != nil || strings.TrimSpace(string(output)) != "1" {
			t.Fatalf("%s reported success with forwarding disabled in the owned namespace: %v", phase, err)
		}
		var checkpoint unix.Timespec
		if err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &checkpoint); err != nil {
			t.Fatal(err)
		}
		wait, cancel := context.WithTimeout(ctx, 25*time.Second)
		_, err = flow.Checkpoint(wait, checkpoint.Nano())
		cancel()
		if err != nil {
			t.Fatalf("%s did not preserve the same TCP and UDP sockets: %v", phase, err)
		}
		if phase == "rules-confirmed" {
			supervisor.mu.Lock()
			err = supervisor.api.cmd.Process.Signal(syscall.SIGUSR2)
			supervisor.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	traffic, err := flow.Stop()
	if err != nil || traffic.TCPAccepted != 1 || traffic.TCPDisconnects != 0 || traffic.UDPTupleChanges != 0 {
		t.Fatalf("retained connection evidence invalid: %v", err)
	}
	nativeDHCPJobsKernelV4(t, ctx, ns[0], bound.Grant.Snapshot)
	helper, _ := supervisor.PIDs()
	nativeDHCPRulesCutEvidenceV4(t, logs.String(), helper)
	t.Log("Both cycles retained the original DHCP grant and used one persistent TCP connection and UDP flow")
}

func nativeDHCPRulesCutEvidenceV4(t *testing.T, log string, helper int) {
	t.Helper()
	phases := []string{"rule_hold_close", "rule_hold_replace", "rule_hold_release"}
	var spans []nativeLeaseSpanEvidenceV4
	for _, line := range strings.Split(log, "\n") {
		payload, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_SPAN_V4 ")
		if !ok {
			continue
		}
		var span nativeLeaseSpanEvidenceV4
		if json.Unmarshal([]byte(payload), &span) != nil || span.PID != helper || !strings.HasPrefix(span.Phase, "rule_hold_") {
			continue
		}
		if span.Truncated || span.Phase != phases[len(spans)%len(phases)] || span.Start <= 0 || span.End < span.Start ||
			len(spans) > 0 && span.Start < spans[len(spans)-1].End {
			t.Fatal("invalid ordering or truncated forwarding barrier measurements")
		}
		spans = append(spans, span)
	}
	cycles := []string{"commit_confirmed", "commit_expired", "rollback_timeout"}
	if len(spans) != len(phases)*len(cycles) {
		t.Fatalf("missing forwarding barrier evidence: %d spans", len(spans))
	}
	for i, operation := range cycles {
		close, replace, release := spans[i*3], spans[i*3+1], spans[i*3+2]
		t.Logf("ANDEIVA_NATIVE_RULE_CUT operation=%s lower_ms=%.3f upper_ms=%.3f close_ms=%.3f before_readback_ms=%.3f replace_ms=%.3f target_readback_ms=%.3f release_ms=%.3f",
			operation, nativeRuleMilliseconds(release.Start-close.End), nativeRuleMilliseconds(release.End-close.Start),
			nativeRuleMilliseconds(close.End-close.Start), nativeRuleMilliseconds(replace.Start-close.End),
			nativeRuleMilliseconds(replace.End-replace.Start), nativeRuleMilliseconds(release.Start-replace.End),
			nativeRuleMilliseconds(release.End-release.Start))
	}
}

func nativeRuleMilliseconds(ns int64) float64 { return float64(ns) / float64(time.Millisecond) }

func nativeDHCPRulesServeV4(ctx context.Context, r *RoutedOperationsRuntimeV3, binding adminauth.SessionBinding, initial string, grant configpoc.RoutedDHCPGrantV3, acks <-chan os.Signal) error {
	select {
	case <-acks:
	case <-ctx.Done():
		return ctx.Err()
	}
	publish := func(phase, revision string) error {
		r.DHCP.mu.Lock()
		latest, err := r.DHCP.remote.Current(ctx)
		r.DHCP.mu.Unlock()
		if err != nil || !reflect.DeepEqual(latest, grant) {
			return errors.Join(err, errors.New("native rules test changed the WAN grant"))
		}
		return nativeDHCPJobsReportEmitV4(phase, revision, latest)
	}
	for _, confirm := range []bool{true, false} {
		candidate, err := nativeDHCPJobsCandidateV4()
		if err != nil {
			return err
		}
		if confirm {
			rule := candidate.Config.Routed.Rules[0]
			rule.ID, rule.Action = "retained-rules-deny", "deny"
			rule.DestinationPorts.From, rule.DestinationPorts.To = 18083, 18083
			candidate.Config.Routed.Rules = append(candidate.Config.Routed.Rules, rule)
		}
		for _, request := range []configpoc.OperationRequestV2{{Kind: configpoc.OpStage, Config: &candidate.Config}, {Kind: configpoc.OpValidate}} {
			if _, err = nativeDHCPJobsOperationV4(ctx, r, binding, request, true); err != nil {
				return err
			}
		}
		seconds := uint64(30)
		committed, err := nativeDHCPJobsOperationV4(ctx, r, binding, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}, true)
		if err != nil || committed.Current.Confirmation == nil {
			return errors.Join(err, errors.New("native rules Commit lacks its pending confirmation"))
		}
		if confirm {
			result, err := nativeDHCPJobsOperationV4(ctx, r, binding, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.RunningRevision}, false)
			if err != nil || result.Current.Confirmation != nil || result.Current.RunningRevision == initial {
				return errors.Join(err, errors.New("native rules Confirm did not select the revised policy"))
			}
			initial = result.Current.RunningRevision
			if err = publish("rules-confirmed", initial); err != nil {
				return err
			}
			select {
			case <-acks:
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		deadline := committed.Current.Confirmation.Deadline
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		closed, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		retry := time.NewTicker(200 * time.Millisecond)
		defer retry.Stop()
		for {
			err = nativeDHCPJobsInspectV4(closed, r)
			status, readErr := r.Service.Status(binding)
			if err == nil && readErr == nil && status.Confirmation == nil && status.RunningRevision == initial && !status.RecoveryRequired {
				if err = publish("rules-reverted", status.RunningRevision); err != nil {
					return err
				}
				// Keep the gateway alive while the parent checks the same sockets.
				<-ctx.Done()
				return nil
			}
			select {
			case <-closed.Done():
				return fmt.Errorf("native rules Confirm expired but rollback did not verify: %w", errors.Join(err, readErr, closed.Err()))
			case <-retry.C:
			}
		}
	}
	return errors.New("native rules test did not exercise Confirm expiry")
}
