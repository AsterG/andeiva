package configpoc

import "strconv"

// The semantic key is the actual global sequence, not its modulo position.
// A fixed 16-nibble path bounds lookup and insertion independently of lifetime.
type v2ClosingIndexNode struct {
	Format    string     `json:"format"`
	Kind      string     `json:"kind"`
	Depth     int        `json:"depth"`
	Children  [16]string `json:"children"`
	Sequence  uint64     `json:"sequence,string"`
	Operation string     `json:"operation"`
}

func validClosingNodeV2(n v2ClosingIndexNode, depth int) bool {
	if n.Format != v2Format || n.Kind != "closing_catalogue.v1" || n.Depth != depth || depth < 0 || depth > 16 {
		return false
	}
	count := 0
	for _, child := range n.Children {
		if child != "" {
			if !validHash(child) {
				return false
			}
			count++
		}
	}
	if depth == 16 {
		return count == 0 && n.Sequence != 0 && validHash(n.Operation)
	}
	return count > 0 && n.Sequence == 0 && n.Operation == ""
}

func (s *v2Store) closingIndexGet(root string, sequence uint64) (string, error) {
	if sequence == 0 || sequence > s.state.HighWater {
		return "", errV2NotFound
	}
	key := closingSequenceKeyV2(sequence)
	for depth := 0; depth <= 16; depth++ {
		if root == "" {
			return "", errV2NotFound
		}
		var n v2ClosingIndexNode
		if s.readObject(root, &n) != nil || !validClosingNodeV2(n, depth) {
			return "", errV2Unavailable
		}
		if depth == 16 {
			if n.Sequence != sequence {
				return "", errV2Unavailable
			}
			return n.Operation, nil
		}
		digit, err := strconv.ParseUint(key[depth:depth+1], 16, 4)
		if err != nil {
			return "", errV2Invalid
		}
		root = n.Children[digit]
	}
	return "", errV2Unavailable
}

func (s *v2Store) closingIndexPut(root string, depth int, sequence uint64, operation string) (string, error) {
	if sequence == 0 || depth < 0 || depth > 16 || (operation != "" && !validHash(operation)) {
		return "", errV2Invalid
	}
	n := v2ClosingIndexNode{Format: v2Format, Kind: "closing_catalogue.v1", Depth: depth}
	if root != "" && (s.readObject(root, &n) != nil || !validClosingNodeV2(n, depth)) {
		return "", errV2Unavailable
	}
	if depth == 16 {
		if root != "" && n.Sequence != sequence {
			return "", errV2Unavailable
		}
		if operation == "" {
			return "", nil
		}
		n.Sequence, n.Operation = sequence, operation
		return s.object(n)
	}
	key := closingSequenceKeyV2(sequence)
	digit, _ := strconv.ParseUint(key[depth:depth+1], 16, 4)
	child, err := s.closingIndexPut(n.Children[digit], depth+1, sequence, operation)
	if err != nil {
		return "", err
	}
	n.Children[digit] = child
	empty := true
	for _, hash := range n.Children {
		if hash != "" {
			empty = false
			break
		}
	}
	if empty {
		return "", nil
	}
	return s.object(n)
}

func (s *v2Store) catalogueHashV2(sequence uint64) (string, error) {
	if s.state.RecoveryReserveVersion == 1 {
		hash, err := s.closingIndexGet(s.state.ClosingIndexRoot, sequence)
		if err == nil {
			return hash, nil
		}
		if err != errV2NotFound {
			return "", err
		}
	}
	hash, err := s.indexGet(s.state.Index, sequence)
	if err != nil {
		return "", err
	}
	if s.state.RecoveryReserveVersion == 1 {
		var op v2Operation
		if s.readObject(hash, &op) != nil {
			return "", errV2Unavailable
		}
		if op.Sequence != sequence {
			return "", errV2NotFound
		}
	}
	return hash, nil
}

// Full scans are used only by explicit namespace retirement, not user listing.
// They walk at most the fixed catalogue capacity and never build a lifetime map.
func (s *v2Store) closingIndexVisit(root string, depth int, visit func(v2Operation) error) error {
	if depth != 0 {
		return errV2Invalid
	}
	return s.closingIndexVisitAt(root, depth, "", visit)
}

func (s *v2Store) closingIndexVisitAt(root string, depth int, prefix string, visit func(v2Operation) error) error {
	if root == "" {
		return nil
	}
	var n v2ClosingIndexNode
	if s.readObject(root, &n) != nil || !validClosingNodeV2(n, depth) {
		return errV2Unavailable
	}
	if depth == 16 {
		var op v2Operation
		if closingSequenceKeyV2(n.Sequence)[:16] != prefix || s.readObject(n.Operation, &op) != nil || op.Sequence != n.Sequence || !s.validOperation(op) || op.ClosingCredit == "" {
			return errV2Unavailable
		}
		return visit(op)
	}
	for i, child := range n.Children {
		if err := s.closingIndexVisitAt(child, depth+1, prefix+strconv.FormatInt(int64(i), 16), visit); err != nil {
			return err
		}
	}
	return nil
}
