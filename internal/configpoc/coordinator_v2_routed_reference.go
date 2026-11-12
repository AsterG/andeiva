package configpoc

// RoutedWorkReferenceV1 is a correlation value, not activation authority. The
// helper must reconstruct a private selected plan from its pinned store before
// any effect. This value cannot construct or validate a RoutedSelectedPlanV1.
type RoutedWorkReferenceV1 struct {
	Work       string
	Lineage    string
	Generation uint64
}

func (p RoutedSelectedPlanV1) Reference() RoutedWorkReferenceV1 {
	if !p.Valid() {
		return RoutedWorkReferenceV1{}
	}
	_, hash, err := v2Canonical(p.work)
	if err != nil {
		return RoutedWorkReferenceV1{}
	}
	return RoutedWorkReferenceV1{Work: hash, Lineage: p.work.Lineage, Generation: p.work.Generation}
}
