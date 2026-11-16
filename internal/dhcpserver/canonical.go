package dhcpserver

import (
	"cmp"
	"encoding/json"
	"slices"
)

// Canonical validates desired LAN bindings and returns an independent value.
// DNS and NTP order is retained because it can express client preference.
// This does not prove live interface ownership or authorize a server process.
func Canonical(input Config, bindings []Binding) (Config, error) {
	if input.Validate(bindings) != nil {
		return Config{}, ErrInvalid
	}
	out := input
	out.Scopes = append([]Scope{}, input.Scopes...)
	for i := range out.Scopes {
		s := &out.Scopes[i]
		s.Pools = append([]Pool{}, s.Pools...)
		s.Excluded = append([]string{}, s.Excluded...)
		s.Reservations = append([]Reservation{}, s.Reservations...)
		s.DNS = append([]string{}, s.DNS...)
		s.NTP = append([]string{}, s.NTP...)
		slices.SortFunc(s.Pools, func(a, b Pool) int {
			if n := cmp.Compare(a.First, b.First); n != 0 {
				return n
			}
			return cmp.Compare(a.Last, b.Last)
		})
		slices.Sort(s.Excluded)
		slices.SortFunc(s.Reservations, func(a, b Reservation) int { return cmp.Compare(a.MAC, b.MAC) })
	}
	slices.SortFunc(out.Scopes, func(a, b Scope) int { return cmp.Compare(a.ID, b.ID) })
	data, err := json.Marshal(out)
	if err != nil || len(data) > MaxConfigBytes {
		return Config{}, ErrInvalid
	}
	return out, nil
}
