package adminauth

import (
	"net/netip"
	"time"
)

const (
	loginAttemptsPerSecond = 4
	loginOriginSlots       = 128
	loginOriginLifetime    = time.Minute
)

type loginBudget struct {
	window   time.Time
	attempts uint8
}

func (b *loginBudget) allow(now time.Time) bool {
	if b.attempts == 0 || now.Sub(b.window) >= time.Second {
		b.window, b.attempts = now, 0
	}
	if b.attempts >= loginAttemptsPerSecond {
		return false
	}
	b.attempts++
	return true
}

type originBudget struct {
	source netip.Addr
	budget loginBudget
}

type loginAdmission struct {
	anonymous loginBudget
	verified  loginBudget
	origins   [loginOriginSlots]originBudget
}

// Rejected attempts never extend retention, and active entries are not evicted
// to make space for an attacker-controlled origin. Verified logins bypass this
// table but retain their separate process-wide budget and the session limit.
func (a *loginAdmission) allowAnonymous(source netip.Addr, now time.Time) bool {
	if !a.anonymous.allow(now) {
		return false
	}
	available := -1
	existing := -1
	for i := range a.origins {
		entry := &a.origins[i]
		if entry.source.IsValid() && now.Sub(entry.budget.window) >= loginOriginLifetime {
			*entry = originBudget{}
		}
		if entry.source == source {
			existing = i
		}
		if available < 0 && !entry.source.IsValid() {
			available = i
		}
	}
	if existing >= 0 {
		return a.origins[existing].budget.allow(now)
	}
	if available < 0 {
		return false
	}
	a.origins[available] = originBudget{source: source}
	return a.origins[available].budget.allow(now)
}

func validLoginSource(source netip.Addr) bool {
	if !source.IsValid() || source.Zone() != "" {
		return false
	}
	source = source.Unmap()
	return !source.IsUnspecified() && !source.IsMulticast()
}
