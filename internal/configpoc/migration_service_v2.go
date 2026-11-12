package configpoc

import (
	"os"
	"time"
)

// SubjectV2 and LegacyBindingV2 are explicitly authorized cold-migration inputs.
// Neither login equality nor a credential digest implies historical ownership.
type SubjectV2 = v2Subject
type LegacyBindingV2 = v2LegacyBinding
type LegacyFingerprintV2 struct {
	Domain       string `json:"domain"`
	Source       string `json:"source"`
	Tip          string `json:"tip"`
	Sequence     uint64 `json:"sequence,string"`
	Projection   uint64 `json:"projection,string"`
	ReceiptIndex string `json:"receipt_index"`
}

func fingerprintLegacyV2(image v2LegacyImage) LegacyFingerprintV2 {
	return LegacyFingerprintV2{Domain: image.Domain, Source: image.Source, Tip: image.Tip, Sequence: image.Sequence, Projection: image.Projection, ReceiptIndex: image.ReceiptIndex}
}

// NewSubjectIDV2 allocates identity only; it never registers an account or grants
// ownership. The caller must persist it through authorized cold migration.
func NewSubjectIDV2() (string, error) { return v2ID("subject", 1) }

// InspectLegacyV2 acquires the existing source lock and performs a read-only,
// quiescent inspection. It does not invoke legacy Open or staging cleanup.
func InspectLegacyV2(area *os.Root, domain string) (LegacyFingerprintV2, error) {
	if area == nil {
		return LegacyFingerprintV2{}, errV2Invalid
	}
	lock, err := lockLegacyV2(area)
	if err != nil {
		return LegacyFingerprintV2{}, err
	}
	defer lock.Close()
	image, err := inspectLegacyV2(area, domain, nil)
	if err != nil {
		return LegacyFingerprintV2{}, err
	}
	return fingerprintLegacyV2(image), nil
}

// PrepareMigrationV2 checks explicit source fingerprints while holding both
// source locks. It selects storage preparation only, closes its handle, and
// neither applies engines nor activates routes, capabilities or v1 restrictions.
func PrepareMigrationV2(destination, firewall, local *os.Root, expected [2]LegacyFingerprintV2, subjects []SubjectV2, bindings []LegacyBindingV2, budget BudgetV2, now time.Time) error {
	if expected[0].Domain != "firewall" || expected[1].Domain != "local_services" || len(subjects) < 1 || len(subjects) > v2MaximumSubjects || len(bindings) > 2*v2MaximumSubjects {
		return errV2Invalid
	}
	store, err := prepareMigrationExpectedV2(destination, firewall, local, subjects, bindings, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes}, now, nil, &expected)
	if err != nil {
		return err
	}
	return store.close()
}
