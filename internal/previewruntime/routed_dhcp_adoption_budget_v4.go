package previewruntime

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpclient"
)

var errRoutedDHCPAdoptionBudgetV4 = errors.New("ANDEIVA_WAN_UPDATE_BUDGET_EXCEEDED")
var errRoutedDHCPAdoptionClockV4 = errors.New("ANDEIVA_WAN_UPDATE_EVIDENCE_UNAVAILABLE")

type RoutedDHCPDiagnosticsV4 struct {
	Notice           string `json:"notice,omitempty"`
	AdoptionOverruns uint64 `json:"adoption_overruns"`
	MarginClosures   uint64 `json:"margin_closures"`
}

func (r *RoutedDHCPRuntimeV3) DiagnosticsV4() RoutedDHCPDiagnosticsV4 {
	if r == nil {
		return RoutedDHCPDiagnosticsV4{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return RoutedDHCPDiagnosticsV4{r.noticeV4, r.adoptionOverruns, r.marginClosures}
}

// Caller holds runtime.mu. This metadata changes no grant, sequence or deadline.
func (r *RoutedDHCPRuntimeV3) observeHookV4(x RoutedDHCPOwnerFactV3, err error) {
	if r.renewalProfile != RoutedDHCPSameEffectiveRenewalV4 || r.adoptionClock == nil || err != nil || x.Epoch == 0 || x.Fact.Owner != r.owner || x.hookBootNS <= 0 || x.Epoch <= r.hookEpoch {
		return
	}
	r.hookEpoch, r.hookBootNS = x.Epoch, x.hookBootNS
}

func (r *RoutedDHCPRuntimeV3) noteMarginClosedV4(epoch uint64) {
	if epoch == 0 || epoch < r.lastMarginEpoch {
		return
	}
	if r.noticeV4 != "ANDEIVA_WAN_LEASE_MARGIN_INSUFFICIENT" && r.marginClosures < math.MaxUint64 {
		r.marginClosures++
	}
	r.lastMarginEpoch, r.noticeV4 = epoch, "ANDEIVA_WAN_LEASE_MARGIN_INSUFFICIENT"
}

// Only operational V4 assembly supplies adoptionClock. Pure algorithm fixtures
// may supply a deterministic clock; legacy assembly leaves it absent.
func (r *RoutedDHCPRuntimeV3) checkAdoptionBudgetV4(ctx context.Context) error {
	if r.renewalProfile != RoutedDHCPSameEffectiveRenewalV4 || r.adoptionClock == nil || !r.renewalWaiting {
		return nil
	}
	now, clockErr := r.adoptionClock()
	known := clockErr == nil && now > 0 && r.hookEpoch == r.grant.Epoch && r.hookBootNS > 0 && now >= r.hookBootNS
	overrun := known && now-r.hookBootNS > int64(dhcpclient.EarlyRenewalAlphaAdoptionBudgetV4)
	if known && !overrun && r.budgetRejectedEpoch < r.grant.Epoch {
		return nil
	}
	if overrun && r.budgetRejectedEpoch < r.grant.Epoch && r.adoptionOverruns < math.MaxUint64 {
		r.adoptionOverruns++
	}
	if r.grant.Epoch > r.budgetRejectedEpoch {
		r.budgetRejectedEpoch = r.grant.Epoch
	}
	cause := errRoutedDHCPAdoptionBudgetV4
	r.noticeV4 = "ANDEIVA_WAN_UPDATE_BUDGET_EXCEEDED"
	if !known {
		cause = errRoutedDHCPAdoptionClockV4
		r.noticeV4 = "ANDEIVA_WAN_UPDATE_EVIDENCE_UNAVAILABLE"
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	return errors.Join(configpoc.ErrRecovery, cause, r.closeUnder(cleanup))
}
