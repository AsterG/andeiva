package firewallipc

import "github.com/AsterG/andeiva/internal/configpoc"

// RoutedCompensationV3 correlates the helper's independent selected reads.
// Prepare omits Ticket. Recover supplies it with the durably consumed selection.
type RoutedCompensationV3 struct {
	Reference RoutedReferenceV3              `json:"reference"`
	Selection configpoc.SelectionReferenceV2 `json:"selection"`
	Operation string                         `json:"operation"`
	Ticket    string                         `json:"ticket,omitempty"`
}

type RoutedCompensationPreparedV3 struct {
	Ticket string `json:"ticket"`
}

func decodeRoutedCompensationV3(data []byte, recover bool) (*RoutedCompensationV3, error) {
	var p RoutedCompensationV3
	keys := []string{"reference", "selection", "operation"}
	if recover {
		keys = append(keys, "ticket")
	}
	if exactRoutedV3(data, &p, keys) != nil || !p.Reference.Valid() ||
		!ValidRoutedSelectionV3(p.Selection) || p.Selection.WorkHash != p.Reference.Work ||
		p.Selection.Lineage != p.Reference.Lineage || (p.Selection.Mode != "intent" && p.Selection.Mode != "pending") ||
		p.Operation == "" || len(p.Operation) > 128 || (recover && !hashV2(p.Ticket)) {
		return nil, ErrChannel
	}
	return &p, nil
}
