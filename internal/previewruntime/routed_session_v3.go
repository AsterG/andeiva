package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

// RoutedSelectionSourceV3 belongs to trusted helper assembly. Its implementation
// independently reads selected configuration, G1 and reserve banks; request data
// is only correlation. It must reject an action inconsistent with current
// Intent/finality, even if the same original Work also appears in another phase.
type RoutedSelectionSourceV3 interface {
	Resolve(context.Context, firewallipc.RoutedReferenceV3, string) (configpoc.RoutedSelectedPlanV1, error)
	PrepareView(context.Context) (RoutedPreparationViewV3, error)
}

type RoutedPreparationViewV3 struct {
	Baseline *configpoc.RoutedBaselineV1
	Startup  configpoc.RoutedActivationBundleV1
	Saved    configpoc.RoutedActivationBundleV1
}

type RoutedSessionV3 struct {
	controller  sync.Mutex
	authority   configpoc.RoutedAuthorityV1
	source      RoutedSelectionSourceV3
	epoch       uint64
	integrity   *routedIntegrityGateV3
	freshScope  routedFreshScopeProofV3
	rebootScope routedRebootScopeProofV4
	inventory   func(context.Context) (networkinventory.Snapshot, error)
	dhcp        *RoutedDHCPRuntimeV3
	dhcpJobs    routedDHCPJobsSessionV4
}

// This trusted hook runs under controller ownership after a completed full
// inspection. No request supplies its implementation or an activation proof.
type routedDHCPJobsSessionV4 interface {
	Inspect(context.Context, configpoc.SelectionReferenceV2) (bool, error)
	Dispatch(context.Context, firewallipc.RoutedCommandV3) (any, error)
	Invalidate(context.Context) error
}

func NewRoutedSessionV3(authority configpoc.RoutedAuthorityV1, source RoutedSelectionSourceV3) (*RoutedSessionV3, error) {
	if authority == nil || source == nil {
		return nil, ErrIdentity
	}
	identity := authority.Identity()
	if identity.UID == 0 || identity.GID == 0 || identity.Namespace == 0 || identity.Host == 0 || identity.Namespace == identity.Host || !bootPattern.MatchString(identity.BootID) || !ValidRun(identity.RunID) {
		return nil, ErrIdentity
	}
	return &RoutedSessionV3{authority: authority, source: source}, nil
}

// ServeRoutedV3 must receive an assembly-authenticated Unix channel. Controller
// ownership covers the entire call and reply, not merely connection liveness.
// Disconnect does not cancel an effect already in progress or its guardian.
// A replacement writer may open its store only after this handshake succeeds.
func (s *RoutedSessionV3) ServeRoutedV3(ctx context.Context, conn io.ReadWriteCloser, runtimeRun string) error {
	if s == nil || ctx == nil || conn == nil || ctx.Err() != nil || !ValidRun(runtimeRun) {
		if conn != nil {
			_ = conn.Close()
		}
		return ErrIdentity
	}
	if !s.controller.TryLock() {
		_ = conn.Close()
		return ErrUnavailable
	}
	defer s.controller.Unlock()
	defer conn.Close()
	identity := s.authority.Identity()
	if runtimeRun != identity.RunID || s.epoch == 0xffffffff {
		return ErrIdentity
	}
	s.epoch++
	epoch := s.epoch
	last := epoch << 32
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	reader := bufio.NewReaderSize(conn, firewallipc.RoutedFrameMaxV3)
	read := func(first bool) ([]byte, error) {
		if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			if !first {
				_ = d.SetReadDeadline(time.Time{})
				if _, e := reader.Peek(1); e != nil {
					return nil, e
				}
			}
			_ = d.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
		data, e := reader.ReadSlice('\n')
		if e != nil || len(data) > firewallipc.RoutedFrameMaxV3 {
			return nil, ErrUnavailable
		}
		return data, nil
	}
	write := func(value any) error {
		data, e := json.Marshal(value)
		if e != nil || len(data)+1 > firewallipc.RoutedFrameMaxV3 {
			return ErrUnavailable
		}
		if d, ok := conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = d.SetWriteDeadline(time.Now().Add(3 * time.Second))
		}
		data = append(data, '\n')
		n, e := conn.Write(data)
		if e == nil && n != len(data) {
			return io.ErrShortWrite
		}
		return e
	}
	data, e := read(true)
	if e != nil {
		return ErrUnavailable
	}
	hello, e := firewallipc.DecodeRoutedHelloV3(data, false)
	if e != nil || hello.RuntimeRun != runtimeRun || hello.Namespace != identity.Namespace || (s.integrity != nil) != (len(hello.RequiredFeatures) >= 4) || (s.inventory != nil) != (len(hello.RequiredFeatures) >= 5) || (s.dhcp != nil || s.dhcpJobs != nil) != hello.HasCapability(firewallipc.RoutedDHCPCapabilityV3) || (s.freshScope != nil) != hello.HasCapability(firewallipc.RoutedFreshScopeCapabilityV3) || (s.rebootScope != nil) != hello.HasCapability(firewallipc.RoutedRebootScopeCapabilityV4) {
		return ErrIdentity
	}
	hello.Run = runtimeRun
	hello.Epoch = epoch
	if write(hello) != nil {
		return ErrUnavailable
	}
	for {
		data, e = read(false)
		if e != nil {
			return ErrUnavailable
		}
		request, command, e := firewallipc.DecodeRoutedRequestV3(data, runtimeRun, identity.Namespace, last)
		if e != nil || request.Sequence>>32 != epoch || request.Sequence&0xffffffff == 0 {
			return ErrIdentity
		}
		last = request.Sequence
		timeout := 3 * time.Second
		if command.Verb == "inspect" {
			timeout = configpoc.IntegrityInspectionDeadlineV1
		}
		call, cancel := context.WithTimeout(ctx, timeout)
		diagnosticStarted := firewallipc.RoutedDHCPDiagnosticStartV1(command.Verb)
		payload, operationErr := s.dispatch(call, command)
		diagnosticErr := operationErr
		if diagnosticErr == errRoutedDHCPInitialWaitingV1 {
			diagnosticErr = firewallipc.ErrRoutedDHCPWaitingV1
		}
		firewallipc.RecordRoutedDHCPDiagnosticV1("helper", command.Verb, diagnosticStarted, diagnosticErr, call.Err())
		if operationErr == errRoutedDHCPInitialWaitingV1 && call.Err() != nil {
			operationErr = configpoc.ErrRecovery
		}
		cancel()
		reply := firewallipc.RoutedReplyV3{ProtocolVersion: firewallipc.RoutedProtocolV3, Run: runtimeRun, Sequence: last, Namespace: identity.Namespace, Domain: "routed", Verb: command.Verb}
		if operationErr != nil {
			reply.Error = "ANDEIVA_CONFIG_RECOVERY_REQUIRED"
			if errors.Is(operationErr, configpoc.ErrConflict) {
				reply.Error = "ANDEIVA_CONFIG_CONFLICT"
			}
			if command.Verb == "dhcp_begin" && operationErr == errRoutedDHCPInitialWaitingV1 {
				reply.Error = firewallipc.ErrRoutedDHCPWaitingV1.Error()
			}
			payload = struct{}{}
		}
		reply.Payload, e = json.Marshal(payload)
		if e != nil || write(reply) != nil {
			return ErrUnavailable
		}
	}
}

func (s *RoutedSessionV3) dispatch(ctx context.Context, c firewallipc.RoutedCommandV3) (any, error) {
	if c.Verb == "reboot_scope" {
		if s.rebootScope == nil || !freshScopeAllowedV3(s.integrity) {
			return nil, ErrIdentity
		}
		proof, err := s.rebootScope.ProveRebootScope(ctx, c.FreshScope.Work)
		if !freshScopeAllowedV3(s.integrity) {
			return nil, configpoc.ErrRecovery
		}
		return firewallipc.RoutedRebootScopeResultV4{Evidence: proof}, err
	}
	if c.Verb == "fresh_scope" {
		if s.freshScope == nil || !freshScopeAllowedV3(s.integrity) {
			return nil, ErrIdentity
		}
		proof, err := s.freshScope.ProveFreshScope(ctx, c.FreshScope.Work)
		if !freshScopeAllowedV3(s.integrity) {
			return nil, configpoc.ErrRecovery
		}
		return firewallipc.RoutedFreshScopeResultV3{Evidence: proof}, err
	}
	if firewallipc.RoutedDHCPVerbV3(c.Verb) {
		if s.dhcpJobs != nil {
			return s.dhcpJobs.Dispatch(ctx, c)
		}
		if s.dhcp == nil {
			return nil, ErrIdentity
		}
		return s.dhcp.dispatch(ctx, c)
	}
	switch c.Verb {
	case "inventory":
		if s.inventory == nil {
			return nil, ErrIdentity
		}
		snapshot, e := s.inventory(ctx)
		if e != nil || ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		return firewallipc.EncodeRoutedInventoryV3(snapshot)
	case "inspect":
		if s.integrity == nil {
			return nil, ErrIdentity
		}
		if c.Integrity.Mode == "attach" {
			result, err := s.integrity.attach(ctx, c.Integrity.Selection)
			return firewallipc.RoutedIntegrityResultV3{Mode: "attach", Result: result}, err
		}
		if c.Integrity.Mode == "check" {
			result, err := s.integrity.inspect(ctx, c.Integrity.Selection, s.authority)
			selected := false
			if err == nil && result.State == configpoc.IntegrityCompleteV1 && s.dhcpJobs != nil {
				selected, err = s.dhcpJobs.Inspect(ctx, result.Selection)
				if err != nil {
					result = integrityIncompleteV3(ctx, result.Selection, err)
				}
			}
			if s.dhcpJobs != nil && (err != nil || result.State != configpoc.IntegrityCompleteV1) {
				err = errors.Join(err, s.dhcpJobs.Invalidate(ctx))
			}
			return firewallipc.RoutedIntegrityResultV3{Mode: "check", Result: result, DHCPSelected: selected}, err
		}
		return nil, ErrIdentity
	case "observe":
		receipt, revision, e := s.authority.Observe(ctx)
		return firewallipc.RoutedObservedV3{Receipt: firewallipc.RoutedReceiptV3{Phase: receipt.Phase, ID: receipt.ID, Previous: receipt.Previous, Target: receipt.Target, Deadline: receipt.Deadline}, Revision: revision}, e
	case "prepare", "prepare_boot":
		if c.Verb == "prepare_boot" && s.rebootScope != nil {
			if !freshScopeAllowedV3(s.integrity) {
				return nil, configpoc.ErrRecovery
			}
			preparation, err := s.rebootScope.prepareSelected(ctx, c.Target, c.Baseline)
			if !freshScopeAllowedV3(s.integrity) {
				return nil, configpoc.ErrRecovery
			}
			return firewallipc.RoutedPreparedV3{Preparation: preparation}, err
		}
		if c.Verb == "prepare_boot" && s.freshScope != nil {
			if !freshScopeAllowedV3(s.integrity) {
				return nil, configpoc.ErrRecovery
			}
			preparation, err := s.freshScope.prepareSelected(ctx, c.Target, c.Baseline)
			if !freshScopeAllowedV3(s.integrity) {
				return nil, configpoc.ErrRecovery
			}
			return firewallipc.RoutedPreparedV3{Preparation: preparation}, err
		}
		view, e := s.source.PrepareView(ctx)
		if e != nil {
			return nil, e
		}
		var preparation configpoc.RoutedPreparationV1
		actualBaseline := ""
		if view.Baseline != nil {
			actualBaseline = view.Baseline.Saved.Composite.Hash
		}
		if c.Verb == "prepare_boot" {
			// Startup is independently selected. The requester cannot choose a second
			// saved baseline or use this verb to apply anything.
			if c.Target.Composite.Hash != view.Startup.Composite.Hash {
				return nil, configpoc.ErrConflict
			}
			if c.Baseline != view.Saved.Composite.Hash {
				return nil, configpoc.ErrConflict
			}
			preparation, e = s.authority.PrepareBoot(ctx, c.Target, view.Saved)
		} else {
			if c.Baseline != actualBaseline {
				return nil, configpoc.ErrConflict
			}
			preparation, e = s.authority.Prepare(ctx, c.Target, view.Baseline)
		}
		return firewallipc.RoutedPreparedV3{Preparation: preparation}, e
	}
	purpose := c.Verb
	if purpose == "match" {
		purpose += "_" + c.Side
	}
	var plan configpoc.RoutedSelectedPlanV1
	var e error
	if s.integrity != nil {
		plan, e = s.integrity.resolve(ctx, s.source, c.Reference, purpose)
	} else {
		plan, e = s.source.Resolve(ctx, c.Reference, purpose)
	}
	if e != nil {
		return nil, e
	}
	reference := plan.Reference()
	if !plan.Valid() || reference.Work != c.Reference.Work || reference.Lineage != c.Reference.Lineage || strconv.FormatUint(reference.Generation, 10) != c.Reference.Generation || plan.Scope().Identity != s.authority.Identity() {
		return nil, configpoc.ErrRecovery
	}
	if plan.FreshScopeEvidenceV3() != nil && (s.freshScope == nil || s.freshScope.verifyPlan(ctx, plan) != nil) {
		return nil, configpoc.ErrRecovery
	}
	if plan.RebootScopeEvidenceV4() != nil && (s.rebootScope == nil || s.rebootScope.verifyPlan(ctx, plan) != nil) {
		return nil, configpoc.ErrRecovery
	}
	switch c.Verb {
	case "match":
		e = s.authority.Match(ctx, plan, c.Side)
	case "resume":
		e = s.authority.Resume(ctx, plan)
	case "arm":
		e = s.authority.Arm(ctx, plan)
	case "apply":
		e = s.authority.Apply(ctx, plan)
	case "confirm":
		e = s.authority.Confirm(ctx, plan)
	case "recover":
		e = s.authority.Recover(ctx, plan)
	case "bootstrap":
		e = s.authority.Bootstrap(ctx, plan, plan.Deadline().Add(-10*time.Second))
	default:
		e = ErrIdentity
	}
	return struct{}{}, e
}
