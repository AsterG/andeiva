//go:build linux

package previewruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpclient"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func TestNativeDHCPCutPhaseSpansV4RejectIncompleteAndForeign(t *testing.T) {
	cuts := []nativeDHCPCutV4{{CloseStart: 100, Opened: 150}, {CloseStart: 200, Opened: 250}, {CloseStart: 300, Opened: 350}}
	var lines []string
	var id uint32
	for _, cut := range cuts {
		for _, phase := range []string{"renew_total", "runtime_close", "selected_authority", "verify_owner", "refresh_evidence", "runtime_open", "gate_stage", "gate_open"} {
			id++
			raw, err := json.Marshal(nativeLeaseSpanEvidenceV4{PID: 123, ID: id, Phase: phase, Start: cut.CloseStart + 1, End: cut.Opened - 1})
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, "ANDEIVA_NATIVE_LEASE_SPAN_V4 "+string(raw))
		}
	}
	valid := strings.Join(lines, "\n")
	if spans, err := nativeDHCPCaptureSpansV4(valid, 123, cuts); err != nil || len(spans) != 24 {
		t.Fatal(spans, err)
	}
	for _, bad := range []string{
		strings.Join(lines[:len(lines)-1], "\n"),
		valid + "\n" + lines[0],
		strings.Replace(valid, `"pid":123`, `"pid":124`, 1),
		strings.Replace(valid, `"id":1`, `"id":1024`, 1),
		strings.Replace(valid, `"phase":"gate_open"`, `"phase":"unknown"`, 1),
		strings.Replace(valid, `"end_boot_ns":149`, `"end_boot_ns":99`, 1),
		strings.Replace(valid, `"id":1`, `"id":1,"truncated":true`, 1),
	} {
		if _, err := nativeDHCPCaptureSpansV4(bad, 123, cuts); err == nil {
			t.Fatal("incomplete/invalid phase evidence accepted")
		}
	}
}

func TestNativeDHCPPhaseSpansV4TenCyclesAndBoundedLog(t *testing.T) {
	var cuts []nativeDHCPCutV4
	var log strings.Builder
	id := uint32(900)
	for i := 0; i < 10; i++ {
		cut := nativeDHCPCutV4{CloseStart: int64(100 + i*100), Opened: int64(150 + i*100)}
		cuts = append(cuts, cut)
		for _, phase := range []string{"renew_total", "runtime_close", "selected_authority", "verify_owner", "refresh_evidence", "runtime_open", "gate_stage", "gate_open"} {
			id++
			raw, _ := json.Marshal(nativeLeaseSpanEvidenceV4{PID: 123, ID: id, Phase: phase, Start: cut.CloseStart + 1, End: cut.Opened - 1})
			fmt.Fprintf(&log, "ANDEIVA_NATIVE_LEASE_SPAN_V4 %s\n", raw)
		}
	}
	if spans, err := nativeDHCPCaptureSpansV4(log.String(), 123, cuts); err != nil || len(spans) != 80 {
		t.Fatal("ten samples or IDs beyond old512 bound rejected", err, len(spans))
	}
	for _, capacity := range []int{0, 512 << 10} {
		var b nativeLogV3
		b.limit = capacity
		limit := capacity
		if limit == 0 {
			limit = 64 << 10
		}
		if n, err := b.Write(make([]byte, limit)); err != nil || n != limit {
			t.Fatal("configured log bound rejected", capacity, err)
		}
		if _, err := b.Write([]byte("x")); err == nil || nativeDHCPEvidenceLogValidV4(b.String()) {
			t.Fatal("overflow did not permanently invalidate evidence")
		}
		if _, err := nativeDHCPCaptureSpansV4(log.String()+b.String(), 123, cuts); err == nil {
			t.Fatal("truncated span evidence accepted")
		}
	}
	var invalid nativeLogV3
	invalid.limit = (512 << 10) + 1
	if _, err := invalid.Write(nil); err == nil {
		t.Fatal("unbounded log allowance accepted")
	}
}

func nativeDHCPAdoptionFixtureV4(t *testing.T) (string, []nativeDHCPCutV4) {
	t.Helper()
	var log strings.Builder
	grant := configpoc.RoutedDHCPGrantV3{Epoch: 40, Snapshot: dhcpRuntimeSnapshotV3(t)}
	writeHook := func(epoch uint64, at int64) {
		raw, _ := json.Marshal(nativeDHCPHookEvidenceV4{123, epoch, at, 120})
		fmt.Fprintf(&log, "ANDEIVA_NATIVE_LEASE_HOOK_V4 %s\n", raw)
	}
	writeReport := func(phase string) {
		raw, _ := json.Marshal(nativeDHCPJobsReportV4{PID: 456, Phase: phase, Running: strings.Repeat("a", 64), Grant: grant})
		fmt.Fprintf(&log, "ANDEIVA_NATIVE_DHCP_JOBS %s\n", raw)
	}
	writeHook(grant.Epoch, 90)
	writeReport("flow-ready")
	var cuts []nativeDHCPCutV4
	for i := 0; i < 10; i++ {
		start := int64(100 + i*100)
		cuts = append(cuts, nativeDHCPCutV4{CloseSequence: grant.Snapshot.Sequence, CloseStart: start, Closed: start + 10, OpenStart: start + 20, Opened: start + 30, LowerNS: 10, UpperNS: 30})
		grant.Epoch++
		grant.Snapshot = dhcpRuntimeRenewedSnapshotV4(t, grant.Snapshot)
		writeHook(grant.Epoch, start+1)
		writeReport(fmt.Sprintf("renewal-%d", i+1))
	}
	return log.String(), cuts
}

func TestNativeDHCPHookToOpenV4CorrelationAndNegatives(t *testing.T) {
	valid, cuts := nativeDHCPAdoptionFixtureV4(t)
	adoptions, err := nativeDHCPAdoptionsV4(valid, 123, 456, 95, cuts)
	if err != nil || len(adoptions) != 10 || adoptions[0].Epoch != 41 || adoptions[0].PreviousSequence != 1 || adoptions[0].Sequence != 2 || adoptions[9].Epoch != 50 || adoptions[9].DurationNS != 29 {
		t.Fatal("epoch was confused with independent fence sequence", adoptions, err)
	}
	lines := strings.Split(strings.TrimSpace(valid), "\n")
	for _, bad := range []string{
		strings.Join(lines[1:], "\n"),
		valid + "\n" + lines[0],
		valid + "\n" + lines[1],
		strings.Replace(valid, `"pid":123`, `"pid":456`, 1),
		strings.Replace(valid, `"pid":456`, `"pid":123`, 1),
		strings.Replace(valid, `"epoch":41`, `"epoch":42`, 1),
		strings.Replace(valid, `"hook_boot_ns":101`, `"hook_boot_ns":131`, 1),
		strings.Replace(valid, `"hook_boot_ns":90`, `"hook_boot_ns":96`, 1),
		strings.Replace(valid, `"lease_seconds":120`, `"lease_seconds":0`, 1),
		strings.Replace(valid, `"hook_boot_ns":90`, `"hook_boot_ns":90,"hook_boot_ns":91`, 1),
		strings.Replace(valid, `"phase":"renewal-1"`, `"phase":"renewal-2"`, 1),
		valid + "ANDEIVA_NATIVE_LOG_TRUNCATED_V3\n",
		valid + "ANDEIVA_NATIVE_LEASE_HOOK_V4 {} {}\n",
	} {
		if _, err := nativeDHCPAdoptionsV4(bad, 123, 456, 95, cuts); err == nil {
			t.Fatal("ambiguous/foreign/truncated evidence accepted")
		}
	}
	badCuts := append([]nativeDHCPCutV4(nil), cuts...)
	badCuts[0].CloseSequence = 99
	if _, err := nativeDHCPAdoptionsV4(valid, 123, 456, 95, badCuts); err == nil {
		t.Fatal("cut not bound to prior opened fence accepted")
	}
	if _, err := nativeDHCPAdoptionsV4(valid, 123, 123, 95, cuts); err == nil {
		t.Fatal("helper and API identity conflated")
	}
}

func TestNativeDHCPEarlyBudgetsV4Boundaries(t *testing.T) {
	cuts := make([]nativeDHCPCutV4, 10)
	adoptions := make([]nativeDHCPAdoptionEvidenceV4, 10)
	for i := range cuts {
		cuts[i].UpperNS = int64(10 * time.Second)
		adoptions[i].DurationNS = int64(12 * time.Second)
	}
	if err := nativeDHCPEarlyBudgetsV4(cuts, adoptions); err != nil {
		t.Fatal("approved boundary rejected", err)
	}
	cuts[9].UpperNS++
	if err := nativeDHCPEarlyBudgetsV4(cuts, adoptions); err == nil {
		t.Fatal("cut budget overrun accepted")
	}
	cuts[9].UpperNS--
	adoptions[9].DurationNS++
	if err := nativeDHCPEarlyBudgetsV4(cuts, adoptions); err == nil {
		t.Fatal("adoption budget overrun accepted")
	}
	if err := nativeDHCPEarlyBudgetsV4(cuts[:9], adoptions[:9]); err == nil {
		t.Fatal("partial sample set accepted")
	}
}

type nativeLeasePhaseEvidenceV4 struct {
	PID               int    `json:"pid"`
	BootNS            int64  `json:"boot_ns"`
	Phase             string `json:"phase"`
	Sequence          uint64 `json:"sequence"`
	ConservativeFloor int64  `json:"conservative_floor_boot_ns,omitempty"`
}

// Kernel effects occur between the before-write and successful-readback marks.
// Lower/upper bounds are measurements, not an invented exact kernel timestamp.
type nativeDHCPCutV4 struct {
	CloseSequence uint64 `json:"close_sequence"`
	CloseStart    int64  `json:"close_start_boot_ns"`
	Closed        int64  `json:"closed_verified_boot_ns"`
	OpenStart     int64  `json:"open_start_boot_ns"`
	Opened        int64  `json:"opened_verified_boot_ns"`
	LowerNS       int64  `json:"lower_bound_ns"`
	UpperNS       int64  `json:"upper_bound_ns"`
}

type nativeLeaseSpanEvidenceV4 struct {
	PID       int    `json:"pid"`
	ID        uint32 `json:"id"`
	Phase     string `json:"phase"`
	Start     int64  `json:"start_boot_ns"`
	End       int64  `json:"end_boot_ns"`
	Truncated bool   `json:"truncated,omitempty"`
}

func nativeDHCPCaptureSpansV4(log string, helperPID int, cuts []nativeDHCPCutV4) ([]nativeLeaseSpanEvidenceV4, error) {
	if helperPID <= 1 || len(cuts) < 3 || len(cuts) > 10 || !nativeDHCPEvidenceLogValidV4(log) {
		return nil, errors.New("invalid phase capture scope")
	}
	seen := map[uint32]bool{}
	var spans []nativeLeaseSpanEvidenceV4
	for _, line := range strings.Split(log, "\n") {
		raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_SPAN_V4 ")
		if !ok {
			continue
		}
		var s nativeLeaseSpanEvidenceV4
		if routedDHCPOwnerDecodeV3([]byte(raw), &s) != nil || s.PID != helperPID || s.ID == 0 || s.ID >= 1024 || seen[s.ID] || s.Start <= 0 || s.End < s.Start || s.Truncated {
			return nil, errors.New("invalid or truncated phase span")
		}
		switch s.Phase {
		case "renew_total", "runtime_close", "current_evidence", "selected_authority", "verify_owner", "refresh_evidence", "runtime_open", "gate_stage", "gate_open", "rpc_wait":
		default:
			return nil, errors.New("unknown phase span")
		}
		seen[s.ID] = true
		spans = append(spans, s)
	}
	for _, cut := range cuts {
		found := map[string]bool{}
		for _, s := range spans {
			if s.Start < cut.Opened && s.End > cut.CloseStart {
				found[s.Phase] = true
			}
		}
		for _, phase := range []string{"renew_total", "runtime_close", "selected_authority", "verify_owner", "refresh_evidence", "runtime_open", "gate_stage", "gate_open"} {
			if !found[phase] {
				return nil, errors.New("incomplete renewal phase measurement: " + phase)
			}
		}
	}
	return spans, nil
}

func nativeDHCPReportPhasesV4(t *testing.T, log string, helperPID int, cuts []nativeDHCPCutV4) {
	t.Helper()
	spans, err := nativeDHCPCaptureSpansV4(log, helperPID, cuts)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range spans {
		for _, cut := range cuts {
			if s.Start < cut.Opened && s.End > cut.CloseStart {
				t.Logf("ANDEIVA_NATIVE_LEASE_SPAN_V4 {\"pid\":%d,\"id\":%d,\"phase\":%q,\"start_boot_ns\":%d,\"end_boot_ns\":%d}", s.PID, s.ID, s.Phase, s.Start, s.End)
				break
			}
		}
	}
	t.Log("Phase spans are nested measurements: do not sum inclusive parent and child durations. RPC total is separate from its transport/queue remainder.")
}

func nativeDHCPCutsV4(log string, helperPID int, readyNS int64) ([]nativeDHCPCutV4, error) {
	if helperPID <= 1 || readyNS <= 0 || !nativeDHCPEvidenceLogValidV4(log) {
		return nil, errors.New("invalid native phase identity/readiness")
	}
	var cuts []nativeDHCPCutV4
	var cut *nativeDHCPCutV4
	var last int64
	var count int
	var closingSequence uint64
	opened, opening := false, false
	for _, line := range strings.Split(log, "\n") {
		raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_PHASE_V4 ")
		if !ok {
			continue
		}
		count++
		var p nativeLeasePhaseEvidenceV4
		if count > 128 || routedDHCPOwnerDecodeV3([]byte(raw), &p) != nil || p.PID != helperPID || p.BootNS <= 0 || p.BootNS < last || p.ConservativeFloor < 0 || p.ConservativeFloor > p.BootNS {
			return nil, errors.New("invalid or truncated native lease phase evidence")
		}
		last = p.BootNS
		switch p.Phase {
		case "close_start":
			if p.Sequence == 0 || opening || closingSequence != 0 {
				return nil, errors.New("unverified open attempt interrupts cut evidence")
			}
			if opened && cut == nil {
				start := p.BootNS
				if p.ConservativeFloor > 0 && p.ConservativeFloor < start {
					start = p.ConservativeFloor
				}
				cut = &nativeDHCPCutV4{CloseStart: start, CloseSequence: p.Sequence}
			}
			closingSequence = p.Sequence
			opened = false
		case "closed":
			if closingSequence == 0 || p.Sequence != closingSequence || p.ConservativeFloor != 0 {
				return nil, errors.New("invalid closed proof frame")
			}
			closingSequence = 0
			if cut != nil && cut.Closed == 0 {
				cut.Closed = p.BootNS
			}
		case "open_start":
			if p.Sequence != 0 || p.ConservativeFloor != 0 || opening || opened || closingSequence != 0 {
				return nil, errors.New("duplicate or invalid open start")
			}
			opening = true
			if cut != nil {
				if cut.Closed == 0 || cut.OpenStart != 0 {
					return nil, errors.New("open without a complete closed proof")
				}
				cut.OpenStart = p.BootNS
			}
		case "opened":
			if !opening || p.Sequence != 0 || p.ConservativeFloor != 0 {
				return nil, errors.New("opened without an attempt")
			}
			opening = false
			if cut != nil {
				if cut.Closed == 0 || cut.OpenStart == 0 {
					return nil, errors.New("missing cut boundaries")
				}
				cut.Opened = p.BootNS
				cut.LowerNS = cut.OpenStart - cut.Closed
				cut.UpperNS = cut.Opened - cut.CloseStart
				if cut.LowerNS < 0 || cut.UpperNS < cut.LowerNS {
					return nil, errors.New("invalid cut duration bounds")
				}
				if cut.CloseStart >= readyNS {
					cuts = append(cuts, *cut)
				}
				cut = nil
			}
			opened = true
		default:
			return nil, errors.New("unknown native lease phase")
		}
	}
	// Only completed cycles are returned. A later incomplete withdrawal cannot
	// be presented as a measured renewal; the caller requires its exact sample count.
	return cuts, nil
}

func nativeDHCPEvidenceLogValidV4(log string) bool {
	return len(log) <= 512<<10 && !strings.Contains(log, "ANDEIVA_NATIVE_LOG_TRUNCATED_V3")
}

type nativeDHCPHookEvidenceV4 struct {
	PID          int    `json:"pid"`
	Epoch        uint64 `json:"epoch"`
	HookBootNS   int64  `json:"hook_boot_ns"`
	LeaseSeconds uint32 `json:"lease_seconds"`
}

type nativeDHCPAdoptionEvidenceV4 struct {
	Cycle            int    `json:"cycle"`
	Epoch            uint64 `json:"epoch"`
	PreviousSequence uint64 `json:"previous_sequence"`
	Sequence         uint64 `json:"sequence"`
	HookBootNS       int64  `json:"hook_boot_ns"`
	OpenedBootNS     int64  `json:"opened_boot_ns"`
	DurationNS       int64  `json:"hook_to_open_ns"`
}

func nativeDHCPJobsReportDecodeV4(raw []byte, report *nativeDHCPJobsReportV4) error {
	// This pre-existing test report embeds Go's untagged Epoch/Snapshot keys.
	// Match its exact serialized shape, including case, rather than accepting
	// encoding/json aliases or changing a shared product type for diagnostics.
	if len(raw) > 32<<10 || !jsoncheck.UniqueFields(raw) || json.Unmarshal(raw, report) != nil {
		return errors.New("invalid native API report")
	}
	canonical, err := json.Marshal(report)
	if err != nil || !continuitySameShapeV4(canonical, raw) {
		return errors.New("non-exact native API report")
	}
	return nil
}

// Epoch is acquisition identity; Sequence is the helper's independent fence.
// Bind both through the API's authenticated baseline/renewal snapshots instead
// of assuming their counters are equal. Only helper PID emits hook evidence.
func nativeDHCPAdoptionsV4(log string, helperPID, apiPID int, readyNS int64, cuts []nativeDHCPCutV4) ([]nativeDHCPAdoptionEvidenceV4, error) {
	if !nativeDHCPEvidenceLogValidV4(log) || helperPID <= 1 || apiPID <= 1 || helperPID == apiPID || readyNS <= 0 || len(cuts) != 10 {
		return nil, errors.New("invalid adoption evidence scope")
	}
	hooks := map[uint64]nativeDHCPHookEvidenceV4{}
	reports := map[string]nativeDHCPJobsReportV4{}
	var lastHook nativeDHCPHookEvidenceV4
	var lastReportIndex int
	for _, line := range strings.Split(log, "\n") {
		if raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_LEASE_HOOK_V4 "); ok {
			var h nativeDHCPHookEvidenceV4
			if len(hooks) >= 128 || routedDHCPOwnerDecodeV3([]byte(raw), &h) != nil || h.PID != helperPID || h.Epoch == 0 || h.Epoch <= lastHook.Epoch || h.HookBootNS <= lastHook.HookBootNS || h.LeaseSeconds != 120 {
				return nil, errors.New("invalid helper hook evidence")
			}
			hooks[h.Epoch] = h
			lastHook = h
		}
		if raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_DHCP_JOBS "); ok {
			var r nativeDHCPJobsReportV4
			if nativeDHCPJobsReportDecodeV4([]byte(raw), &r) != nil || r.PID != apiPID {
				return nil, errors.New("invalid API renewal evidence")
			}
			index := -1
			if r.Phase == "flow-ready" {
				index = 0
			}
			for i := 1; i <= 10; i++ {
				if r.Phase == fmt.Sprintf("renewal-%d", i) {
					index = i
				}
			}
			if index < 0 {
				if strings.HasPrefix(r.Phase, "renewal-") {
					return nil, errors.New("unknown renewal report")
				}
				continue
			}
			if _, exists := reports[r.Phase]; exists || index > 0 && index != lastReportIndex+1 || index == 0 && len(reports) != 0 {
				return nil, errors.New("duplicate or out-of-order renewal evidence")
			}
			reports[r.Phase] = r
			lastReportIndex = index
		}
	}
	baseline, ok := reports["flow-ready"]
	hook, hasHook := hooks[baseline.Grant.Epoch]
	if !ok || !hasHook || hook.HookBootNS > readyNS || !routedPrivateHashV4(baseline.Running) || baseline.Grant.Epoch == 0 || baseline.Grant.Snapshot.Sequence == 0 || len(reports) != 11 {
		return nil, errors.New("missing or ambiguous pre-READY baseline")
	}
	previous := baseline.Grant
	previousHook := hook.HookBootNS
	var out []nativeDHCPAdoptionEvidenceV4
	for i, cut := range cuts {
		r, exists := reports[fmt.Sprintf("renewal-%d", i+1)]
		h, existsHook := hooks[r.Grant.Epoch]
		if !exists || !existsHook || previous.Epoch == ^uint64(0) || r.Grant.Epoch != previous.Epoch+1 || r.Running != baseline.Running || networkexecutor.ValidateSameEffectiveLeaseV4(previous.Snapshot, r.Grant.Snapshot) != nil || cut.CloseSequence != previous.Snapshot.Sequence || cut.CloseStart < readyNS || h.HookBootNS <= readyNS || h.HookBootNS <= previousHook || h.HookBootNS > cut.OpenStart || cut.Closed < cut.CloseStart || cut.OpenStart < cut.Closed || cut.Opened < cut.OpenStart || i > 0 && cut.CloseStart < cuts[i-1].Opened {
			return nil, errors.New("renewal hook/epoch/sequence/cut correlation failed")
		}
		out = append(out, nativeDHCPAdoptionEvidenceV4{i + 1, r.Grant.Epoch, previous.Snapshot.Sequence, r.Grant.Snapshot.Sequence, h.HookBootNS, cut.Opened, cut.Opened - h.HookBootNS})
		previous, previousHook = r.Grant, h.HookBootNS
	}
	return out, nil
}

func nativeDHCPReportAdoptionsV4(t *testing.T, adoptions []nativeDHCPAdoptionEvidenceV4) {
	t.Helper()
	values := make([]int64, len(adoptions))
	for i, a := range adoptions {
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("ANDEIVA_NATIVE_RENEWAL_ADOPTION_V4 %s", raw)
		values[i] = a.DurationNS
	}
	minimum, median, maximum := nativeDurationSummaryV4(values)
	t.Logf("ANDEIVA_NATIVE_ADOPTION_SUMMARY_V4 hook_to_open_ns_min_median_max=%d,%d,%d alpha_max_adoption_ns=%d product_slo=undefined", minimum, median, maximum, int64(dhcpclient.EarlyRenewalAlphaAdoptionBudgetV4))
}

func nativeDHCPEarlyBudgetsV4(cuts []nativeDHCPCutV4, adoptions []nativeDHCPAdoptionEvidenceV4) error {
	if len(cuts) != 10 || len(adoptions) != len(cuts) {
		return errors.New("ten complete cut/adoption samples required")
	}
	for i, cut := range cuts {
		if cut.UpperNS < 0 || cut.UpperNS > int64(dhcpclient.EarlyRenewalAlphaCutBudgetV4) {
			return fmt.Errorf("provisional Alpha cut budget exceeded at cycle %d: %dns; maximum %v", i+1, cut.UpperNS, dhcpclient.EarlyRenewalAlphaCutBudgetV4)
		}
		if adoptions[i].DurationNS < 0 || adoptions[i].DurationNS > int64(dhcpclient.EarlyRenewalAlphaAdoptionBudgetV4) {
			return fmt.Errorf("provisional Alpha hook-to-open budget exceeded at cycle %d: %dns; maximum %v", i+1, adoptions[i].DurationNS, dhcpclient.EarlyRenewalAlphaAdoptionBudgetV4)
		}
	}
	return nil
}

func nativeDurationSummaryV4(values []int64) (minimum, median, maximum int64) {
	if len(values) == 0 {
		return
	}
	v := append([]int64(nil), values...)
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	minimum, maximum = v[0], v[len(v)-1]
	median = v[len(v)/2]
	if len(v)%2 == 0 {
		median = v[len(v)/2-1] + (median-v[len(v)/2-1])/2
	}
	return
}

func TestNativeDHCPCutEvidenceV4BoundsAndStrictFrames(t *testing.T) {
	const initial = "ANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":80,\"phase\":\"open_start\",\"sequence\":0}\nANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":90,\"phase\":\"opened\",\"sequence\":0}\n"
	const cycle = "ANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":100,\"phase\":\"close_start\",\"sequence\":1}\nANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":110,\"phase\":\"closed\",\"sequence\":1}\nANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":120,\"phase\":\"open_start\",\"sequence\":0}\nANDEIVA_NATIVE_LEASE_PHASE_V4 {\"pid\":123,\"boot_ns\":130,\"phase\":\"opened\",\"sequence\":0}\n"
	valid := initial + cycle
	cuts, err := nativeDHCPCutsV4(valid, 123, 95)
	if err != nil || len(cuts) != 1 || cuts[0].LowerNS != 10 || cuts[0].UpperNS != 30 {
		t.Fatal(cuts, err)
	}
	for _, bad := range []string{
		strings.Replace(valid, `"pid":123`, `"pid":124`, 1),
		strings.Replace(valid, `"boot_ns":100`, `"boot_ns":100,"boot_ns":101`, 1),
		strings.Replace(valid, `"phase":"closed"`, `"phase":"truncated"`, 1),
		strings.Replace(valid, `"boot_ns":110`, `"boot_ns":99`, 1),
		strings.Replace(valid, `"phase":"open_start"`, `"phase":"closed"`, 1),
		strings.Replace(valid, `"phase":"closed"`, `"phase":"opened"`, 1),
		strings.Replace(valid, `"phase":"closed","sequence":1`, `"phase":"closed","sequence":999`, 1),
		strings.Replace(valid, `"phase":"close_start"`, `"phase":"closed"`, 1),
		valid + `ANDEIVA_NATIVE_LEASE_PHASE_V4 {"pid":123,"boot_ns":140,"phase":"closed","sequence":1} {}`,
	} {
		if _, err := nativeDHCPCutsV4(bad, 123, 95); err == nil {
			t.Fatal("invalid evidence accepted", bad)
		}
	}
	for _, identity := range []struct {
		pid   int
		ready int64
	}{{0, 95}, {1, 95}, {123, 0}, {123, -1}} {
		if _, err := nativeDHCPCutsV4(valid, identity.pid, identity.ready); err == nil {
			t.Fatal("invalid helper/readiness accepted")
		}
	}
	if cuts, err := nativeDHCPCutsV4(valid, 123, 101); err != nil || len(cuts) != 0 {
		t.Fatal("pre-READY cycle counted")
	}
	if a, b, c := nativeDurationSummaryV4([]int64{30, 10, 20}); a != 10 || b != 20 || c != 30 {
		t.Fatal(a, b, c)
	}
}
