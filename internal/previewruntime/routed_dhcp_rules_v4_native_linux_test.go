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
	"github.com/AsterG/andeiva/internal/dhcpclient"
	"golang.org/x/sys/unix"
)

func TestNativeRoutedDHCPRetainedRulesV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, "rules")
}

const (
	nativeRulesOverlapProfileV4   = "overlap"
	nativeRulesNoRenewalProfileV4 = "noack"
	nativeRulesOverlapLeaseV4     = 180
	// With the current B1 schedule, expiry occurs just after DHCP has closed
	// its gate for the first real renewal. Kernel traces verify the overlap.
	nativeRulesOverlapConfirmV4 = 72
)

func TestNativeRoutedDHCPRetainedRulesOverlapV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, nativeRulesOverlapProfileV4)
}

func TestNativeRoutedDHCPRetainedRulesNoRenewalV4(t *testing.T) {
	nativeRunRoutedDHCPScenarioV4(t, true, 0, nativeRulesNoRenewalProfileV4)
}

func nativeDHCPRulesRootV4(t *testing.T, ctx context.Context, ns [3]*os.File, supervisor *RoutedLaunchSupervisorV3, logs *nativeLogV3, bound nativeDHCPJobsReportV4, profile string, stopServer func()) {
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
	var ready unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ready); err != nil {
		t.Fatal(err)
	}
	if profile == nativeRulesNoRenewalProfileV4 {
		stopServer()
	}
	supervisor.mu.Lock()
	err = supervisor.api.cmd.Process.Signal(syscall.SIGUSR2)
	supervisor.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if profile == nativeRulesNoRenewalProfileV4 {
		nativeDHCPJobsWaitReportV4(t, ctx, logs, "rules-recovery-required")
		if err := nativeDHCPB2ClosedKernelV4(ctx, ns[0]); err != nil {
			t.Fatalf("forwarding did not remain closed after Confirm expired without a new grant: %v", err)
		}
		var verified unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &verified); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Second):
		}
		traffic, err := flow.Stop()
		if err != nil || traffic.TCPLastEchoBootNS <= 0 || traffic.TCPLastEchoBootNS >= verified.Nano() {
			t.Fatalf("expected established TCP to stop receiving data under closed recovery: %v", err)
		}
		probes := 0
		for seq, at := range traffic.UDPSendStartBootNS {
			if at >= verified.Nano() && traffic.UDPSentSet.has(uint64(seq)) {
				probes++
				if traffic.UDPSinkReceivedSet.has(uint64(seq)) {
					t.Fatal("UDP reached the WAN after closed recovery was verified")
				}
			}
		}
		if probes == 0 {
			t.Fatal("no UDP probes during verified closed recovery")
		}
		t.Log("Confirm expired without a new grant. Recovery is required with kernel forwarding and the DHCP permit closed.")
		return
	}
	overlap := profile == nativeRulesOverlapProfileV4
	phases := []string{"rules-confirmed", "rules-reverted"}
	if overlap {
		phases = []string{"rules-reverted"}
	}
	latest := bound.Grant
	for _, phase := range phases {
		report := nativeDHCPJobsWaitReportV4(t, ctx, logs, phase)
		if overlap {
			if !sameRenewalGrantV4(bound.Grant, report.Grant) || report.Running != bound.Running {
				t.Fatal("overlap did not restore the original policy with a verified same-WAN renewal")
			}
		} else if !reflect.DeepEqual(report.Grant, bound.Grant) || report.Running == bound.Running {
			t.Fatalf("%s did not preserve the original WAN grant and select the expected firewall lineage", phase)
		}
		latest = report.Grant
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
	nativeDHCPJobsKernelV4(t, ctx, ns[0], latest.Snapshot)
	helper, _ := supervisor.PIDs()
	if overlap {
		nativeDHCPRulesOverlapEvidenceV4(t, logs.String(), helper, ready.Nano())
		return
	}
	nativeDHCPRulesCutEvidenceV4(t, logs.String(), helper)
	t.Log("Both cycles retained the original DHCP grant and used one persistent TCP connection and UDP flow")
}

func nativeDHCPRulesCutEvidenceV4(t *testing.T, log string, helper int) {
	t.Helper()
	spans := nativeDHCPRulesHoldSpansV4(t, log, helper)
	cycles := []string{"commit_confirmed", "commit_expired", "rollback_timeout"}
	if len(spans) != 3*len(cycles) {
		t.Fatalf("missing forwarding barrier evidence: %d spans", len(spans))
	}
	const alphaForwardingPauseLimit = 500 * time.Millisecond
	for i, operation := range cycles {
		close, replace, release := spans[i*3], spans[i*3+1], spans[i*3+2]
		upper := release.End - close.Start
		t.Logf("ANDEIVA_NATIVE_RULE_CUT operation=%s lower_ms=%.3f upper_ms=%.3f close_ms=%.3f before_readback_ms=%.3f replace_ms=%.3f target_readback_ms=%.3f release_ms=%.3f",
			operation, nativeRuleMilliseconds(release.Start-close.End), nativeRuleMilliseconds(upper),
			nativeRuleMilliseconds(close.End-close.Start), nativeRuleMilliseconds(replace.Start-close.End),
			nativeRuleMilliseconds(replace.End-replace.Start), nativeRuleMilliseconds(release.Start-replace.End),
			nativeRuleMilliseconds(release.End-release.Start))
		if time.Duration(upper) > alphaForwardingPauseLimit {
			t.Errorf("%s forwarding pause exceeded the provisional Alpha limit of %s", operation, alphaForwardingPauseLimit)
		}
	}
}

func nativeDHCPRulesHoldSpansV4(t *testing.T, log string, helper int) []nativeLeaseSpanEvidenceV4 {
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
	return spans
}

func nativeDHCPRulesOverlapEvidenceV4(t *testing.T, log string, helper int, ready int64) {
	t.Helper()
	cuts, err := nativeDHCPCutsV4(log, helper, ready)
	if err != nil || len(cuts) != 1 {
		t.Fatalf("expected one verified DHCP close/open cycle, got %d: %v", len(cuts), err)
	}
	spans := nativeDHCPRulesHoldSpansV4(t, log, helper)
	if len(spans) != 6 {
		t.Fatalf("expected one Commit and one rollback, got %d rule barrier spans", len(spans))
	}
	cut := cuts[0]
	if spans[2].End > cut.CloseStart || cut.Closed > spans[3].Start || cut.OpenStart < spans[5].End {
		t.Fatal("kernel traces do not place the entire rollback inside the verified DHCP closure")
	}
	t.Logf("ANDEIVA_NATIVE_RULE_RENEWAL_OVERLAP lower_ms=%.3f upper_ms=%.3f rollback_ms=%.3f",
		nativeRuleMilliseconds(cut.LowerNS), nativeRuleMilliseconds(cut.UpperNS), nativeRuleMilliseconds(spans[5].End-spans[3].Start))
}

func nativeRuleMilliseconds(ns int64) float64 { return float64(ns) / float64(time.Millisecond) }

func nativeDHCPRulesServeV4(ctx context.Context, r *RoutedOperationsRuntimeV3, binding adminauth.SessionBinding, initial string, grant configpoc.RoutedDHCPGrantV3, acks <-chan os.Signal, profile string) error {
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
	cycles := []bool{true, false}
	overlap := profile == nativeRulesOverlapProfileV4
	noRenewal := profile == nativeRulesNoRenewalProfileV4
	if overlap || noRenewal {
		cycles = []bool{false}
	}
	for _, confirm := range cycles {
		candidate, err := nativeDHCPJobsCandidateV4()
		if err != nil {
			return err
		}
		if confirm || overlap || noRenewal {
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
		if overlap {
			seconds = nativeRulesOverlapConfirmV4
		}
		if noRenewal {
			// The lost response has time to close the permit before expiry.
			seconds = 84
		}
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
		if noRenewal {
			return nativeDHCPRulesWaitClosedV4(ctx, r, binding)
		}
		closed, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		retry := time.NewTicker(200 * time.Millisecond)
		defer retry.Stop()
		for {
			if overlap {
				// Only observe. Manual inspection or Reconcile could hide a
				// failure of the normal rollback/renewal schedulers.
				err = configpoc.ErrRecovery
				if r.Service.RuntimeIntegrityReadyV1() {
					err = nil
				}
			} else {
				err = nativeDHCPJobsInspectV4(closed, r)
			}
			status, readErr := r.Service.Status(binding)
			if err == nil && readErr == nil && status.Confirmation == nil && status.RunningRevision == initial && !status.RecoveryRequired {
				if overlap {
					r.DHCP.mu.Lock()
					latest := r.DHCP.grant
					r.DHCP.mu.Unlock()
					if sameRenewalGrantV4(grant, latest) {
						if err = nativeDHCPJobsReportEmitV4("rules-reverted", status.RunningRevision, latest); err != nil {
							return err
						}
						<-ctx.Done()
						return nil
					}
				} else {
					if err = publish("rules-reverted", status.RunningRevision); err != nil {
						return err
					}
					// Keep the gateway alive while the parent checks the same sockets.
					<-ctx.Done()
					return nil
				}
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

func nativeDHCPRulesWaitClosedV4(ctx context.Context, r *RoutedOperationsRuntimeV3, binding adminauth.SessionBinding) error {
	timer := time.NewTimer(dhcpclient.EarlyRenewalAlphaAdoptionBudgetV4)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	status, err := r.Service.Status(binding)
	if err != nil || !status.RecoveryRequired {
		return errors.Join(err, errors.New("expired Confirm did not expose the recovery-required state"))
	}
	if err = nativeDHCPJobsReportEmitV4("rules-recovery-required", status.RunningRevision, configpoc.RoutedDHCPGrantV3{}); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
