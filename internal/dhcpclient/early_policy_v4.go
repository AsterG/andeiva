package dhcpclient

import "time"

// Provisional Alpha policy approved 2026-11-17. See
// docs/decisions/ADR-072-B1-MEASUREMENTS-20261117.md and README.md.
// No value extends lease authority or constitutes a product guarantee.
const (
	earlyTokenMargin      = 3 * time.Second
	earlyResponse         = 5 * time.Second
	earlyDispatch         = time.Second
	earlyAdoption         = 12 * time.Second
	earlySafety           = time.Second
	earlyResponseDispatch = earlyResponse + earlyDispatch                  // 6s.
	earlyMinimum          = earlyAdoption + earlySafety                    // 13s; never clamp up.
	earlyAdoptionReserve  = earlyAdoption + earlyTokenMargin + earlySafety // 16s.
	earlyWindow           = earlyResponseDispatch + earlyAdoptionReserve   // 22s.
	earlySignalReserve    = earlyResponse + earlyAdoptionReserve
	earlyMinimumLease     = 2*(earlyMinimum+earlyResponseDispatch) + earlyAdoptionReserve // Calendar only:54s.
	// Qualified with default T1=floor(L/2) and measured overhead below 1s.
	// Every grant still has to pass the actual remaining-authority check.
	earlySupportedLease               = 71 * time.Second
	EarlyRenewalAlphaAdoptionBudgetV4 = earlyAdoption
	EarlyRenewalAlphaCutBudgetV4      = 10 * time.Second
)
