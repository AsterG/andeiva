package configpoc

import (
	"fmt"
	"strconv"
	"strings"
)

func (r *v2ReachabilityReader) selection(hash string, expectedPrevious *string) error {
	var previousSelection v2Selection
	var previousState v2State
	for i := 0; i <= 64; i++ {
		var selection v2Selection
		release, err := r.load(hash, &selection)
		if err != nil {
			return err
		}
		release()
		if !v2ValidSelection(selection) || (i == 0 && expectedPrevious != nil && selection.Previous != *expectedPrevious) {
			return errV2Unavailable
		}
		var state v2State
		release, err = r.load(selection.State, &state)
		if err != nil {
			return err
		}
		if !v2ValidState(state) || state.Lineage != selection.Lineage {
			release()
			return errV2Unavailable
		}
		if i == 0 && r.report.State == "" {
			r.report.State = selection.State
			r.report.Sequence = selection.Sequence
			r.report.Lineage = selection.Lineage
		}
		if r.report.Lineage != selection.Lineage {
			release()
			return errV2Unavailable
		}
		if i > 0 && (selection.Sequence+1 != previousSelection.Sequence || !preservesFeaturesV2(state, previousState) || !preservesReclamationV2(state, previousState) || !preservesRecoveryReserveV2(state, previousState) || (!previousSelection.Checkpoint && selection.Segment+1 != previousSelection.Segment) || (previousSelection.Checkpoint && selection.Segment != 64)) {
			release()
			return errV2Unavailable
		}
		err = r.walk("state:"+selection.State, 1, func() error { return r.state(selection.State, state, 2) })
		release()
		if err != nil {
			return err
		}
		if i > 0 && previousSelection.Checkpoint {
			return nil
		}
		if selection.Previous == "" {
			if selection.Sequence != 1 {
				return errV2Unavailable
			}
			return nil
		}
		previousSelection = selection
		// Only the preceding feature set is needed by the selection edge. Do not
		// retain every decoded state while traversing historical selections.
		previousState = v2State{RequiredFeatures: state.RequiredFeatures, ReclamationVersion: state.ReclamationVersion, RecoveryReserveVersion: state.RecoveryReserveVersion, ReserveArchiveRoot: state.ReserveArchiveRoot, Configuration: reserveFreezeSummaryV2(state.Configuration), RoutedBootBoundary: clone(state.RoutedBootBoundary), Generation: state.Generation, RoutedDHCP: clone(state.RoutedDHCP), RoutedDHCPLast: state.RoutedDHCPLast}
		hash = selection.Previous
	}
	return errV2InspectionBudget
}

func (r *v2ReachabilityReader) state(key string, state v2State, depth int) error {
	if validateRoutedBootBoundaryV2(state, r.object) != nil {
		return errV2Unavailable
	}
	if state.RoutedBootBoundary != nil {
		if err := r.routedBootBoundary(state.RoutedBootBoundary, key, state, depth+1); err != nil {
			return err
		}
	}
	if err := reserveMetadataFutureFitsV2(state, r.object); err != nil {
		return err
	}
	if state.Migration != "" {
		var held []func()
		var readErr error
		err := validateMigrationReadV2(state, func(hash string, target any) error {
			release, err := r.load(hash, target)
			if err != nil {
				readErr = err
				return err
			}
			held = append(held, release)
			return nil
		})
		for _, release := range held {
			release()
		}
		if readErr != nil {
			return readErr
		}
		if err != nil {
			return err
		}
	}
	ordinary := uint64(0)
	if state.Index != "" {
		if err := r.index(state.Index, 2, 0, key, state, depth, &ordinary); err != nil {
			return err
		}
	}
	if state.RecoveryReserveVersion == 1 {
		closing := uint64(0)
		if state.ClosingIndexRoot != "" {
			if err := r.closingIndex(state.ClosingIndexRoot, 0, "", key, state, depth, &closing); err != nil {
				return err
			}
		}
		if ordinary != state.OccupiedOrdinary || closing != state.OccupiedClosing {
			return errV2Unavailable
		}
		if state.ReserveArchiveRoot != "" {
			if err := r.reserveArchiveTree(state.ReserveArchiveRoot, 0, "", key, state, depth); err != nil {
				return err
			}
		}
		if err := r.activeReserves(key, state, depth); err != nil {
			return err
		}
	}
	if state.Configuration != nil {
		return r.configuration(*state.Configuration, key, state, depth, true)
	}
	for _, ns := range state.Namespaces {
		for _, id := range namespaceOpenIDsV2(ns) {
			op, err := r.lookup(state, ns.Subject, id)
			if err != nil {
				return err
			}
			_ = op // Catalogue-only preparation has no coordinator intent format.
		}
	}
	return nil
}

func (r *v2ReachabilityReader) index(hash string, level int, prefix uint64, key string, state v2State, depth int, count *uint64) error {
	return r.walk(fmt.Sprintf("index:%s:%s:%d:%d", key, hash, level, prefix), depth, func() error {
		var page v2Page
		release, err := r.load(hash, &page)
		if err != nil {
			return err
		}
		defer release()
		if !v2ValidPage(page, level) {
			return errV2Unavailable
		}
		for i, child := range page.Refs {
			if child == "" {
				continue
			}
			position := prefix*64 + uint64(i)
			if level > 0 {
				if err := r.index(child, level-1, position, key, state, depth+1, count); err != nil {
					return err
				}
				continue
			}
			var op v2Operation
			release, err := r.load(child, &op)
			if err != nil {
				return err
			}
			valid := (&v2Store{state: state}).validOperation(op) && op.Sequence <= state.HighWater && (op.Sequence-1)%state.LiveSlots == position && op.Lineage == state.Lineage
			if state.RecoveryReserveVersion == 0 {
				valid = valid && state.HighWater-op.Sequence < state.LiveSlots
			} else {
				valid = valid && op.ClosingCredit == ""
			}
			if !valid {
				release()
				return errV2Unavailable
			}
			if op.Outcome != nil {
				err = r.operationAudit(op, state, depth+1)
			}
			if !op.Retired {
				*count++
			}
			release()
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *v2ReachabilityReader) lookup(state v2State, subject, id string) (v2Operation, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 4 || parts[0] != "v2" || parts[1] != "op" {
		return v2Operation{}, errV2Unavailable
	}
	seq, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != parts[2] || seq == 0 || seq > state.HighWater {
		return v2Operation{}, errV2Unavailable
	}
	if state.RecoveryReserveVersion == 1 && state.ClosingIndexRoot != "" {
		hash, found, err := r.closingObject(state, seq)
		if err != nil {
			return v2Operation{}, err
		}
		if found {
			var op v2Operation
			if err := r.object(hash, &op); err != nil {
				return op, err
			}
			if !(&v2Store{state: state}).validOperation(op) || op.ID != id || op.Sequence != seq || op.Subject != subject || op.Lineage != state.Lineage || op.ClosingCredit == "" {
				return op, errV2Unavailable
			}
			if r.action != nil && op.Outcome != nil {
				if err := r.operationAudit(op, state, 2); err != nil {
					return op, err
				}
			}
			return op, nil
		}
	}
	position := (seq - 1) % state.LiveSlots
	hash := state.Index
	for level := 2; level >= 0; level-- {
		var page v2Page
		if err := r.object(hash, &page); err != nil {
			return v2Operation{}, err
		}
		if !v2ValidPage(page, level) {
			return v2Operation{}, errV2Unavailable
		}
		hash = page.Refs[(position>>uint(level*6))&63]
	}
	var op v2Operation
	if err := r.object(hash, &op); err != nil {
		return op, err
	}
	if !(&v2Store{state: state}).validOperation(op) || op.ID != id || op.Sequence != seq || op.Subject != subject || op.Lineage != state.Lineage {
		return op, errV2Unavailable
	}
	if r.action != nil && op.Outcome != nil {
		if err := r.operationAudit(op, state, 2); err != nil {
			return op, err
		}
	}
	return op, nil
}

func (r *v2ReachabilityReader) configuration(cfg v2Configuration, key string, state v2State, depth int, live bool) error {
	if !r.selectedConfigurationValidV2(&cfg) {
		return errV2Unavailable
	}
	if live && validateCandidateGroupEvidenceV2(cfg, r.object) != nil {
		return errV2Unavailable
	}
	if live {
		if err := r.routedActive(key, state, depth+1); err != nil {
			return err
		}
	}
	if live && cfg.AuditTip != "" {
		var audit v2CoordinatorAudit
		if err := r.object(cfg.AuditTip, &audit); err != nil {
			return err
		}
		if audit.Generation != state.Generation || audit.Sequence != cfg.AuditSequence || audit.Running != cfg.Running.Hash || audit.Startup != cfg.Startup.Hash {
			return errV2Unavailable
		}
	}
	if live && cfg.Pending == nil && !declaredOfflineSeedV3(state, cfg, r.object) {
		entry, err := r.findWitness(cfg.VerifiedIndex, cfg.Running.Hash)
		if err != nil {
			return err
		}
		var audit v2CoordinatorAudit
		if err := r.object(entry.Audit, &audit); err != nil {
			return err
		}
		if audit.Operation != entry.Operation || audit.Running != cfg.Running.Hash || audit.Sequence > cfg.AuditSequence || (audit.Result != "applied" && audit.Result != "verified") {
			return errV2Unavailable
		}
		if r.action != nil {
			if err := r.actionAuditLeafV2(entry.Audit, audit.Sequence, state.Generation, depth); err != nil {
				return err
			}
		}
	}
	for _, domain := range []v2DomainSnapshot{cfg.Firewall, cfg.LocalServices} {
		for _, revision := range []Revision{domain.Running, domain.Startup, domain.LastGood} {
			if err := r.canonicalConfig(revision.Hash, revision.Config.SchemaVersion, depth); err != nil {
				return err
			}
		}
		if domain.Candidate != nil {
			if err := r.canonicalConfig(domain.Candidate.Revision.Hash, domain.Candidate.Revision.Config.SchemaVersion, depth); err != nil {
				return err
			}
		}
	}
	for _, revision := range []v2CompositeRevision{cfg.Running, cfg.Startup, cfg.LastGood} {
		if err := r.composite(revision.Hash, depth); err != nil {
			return err
		}
	}
	if cfg.Candidate != nil {
		if err := r.composite(cfg.Candidate.Hash, depth); err != nil {
			return err
		}
	}
	if cfg.AuditTip != "" {
		if err := r.auditChain(cfg.AuditTip, cfg.AuditSequence, state.Generation, depth); err != nil {
			return err
		}
	}
	if r.action != nil && !live {
		if cfg.Intent != nil {
			return errV2Unavailable
		}
		return nil
	}
	view := state
	view.Configuration = &cfg
	if r.action == nil && cfg.VerifiedIndex != "" {
		if err := r.witness(cfg.VerifiedIndex, 0, "", false, key, view, depth); err != nil {
			return err
		}
	}
	if r.action == nil && cfg.RecoveryIndex != "" {
		if err := r.witness(cfg.RecoveryIndex, 0, "", true, key, view, depth); err != nil {
			return err
		}
	}
	if cfg.Intent != nil {
		in := cfg.Intent
		if in.RoutedWork != "" {
			if err := r.routedIntent(in, key, state, depth+1); err != nil {
				return err
			}
		}
		if in.TargetGeneration < state.Generation || (in.TargetGeneration != state.Generation && (state.Generation == ^uint64(0) || in.TargetGeneration != state.Generation+1)) {
			return errV2Unavailable
		}
		var sides [2]v2Configuration
		for i, hash := range []string{in.Previous, in.Target} {
			var snapshot v2Configuration
			if err := r.object(hash, &snapshot); err != nil {
				return err
			}
			if snapshot.Intent != nil {
				return errV2Unavailable
			}
			sides[i] = snapshot
			if err := r.snapshot(hash, key, state, depth+1); err != nil {
				return err
			}
		}
		if validateGuardDeadlineContextV2(in, sides[0], sides[1], hasFeatureV2(state, v2GuardDeadlineFeature), live) != nil {
			return errV2Unavailable
		}
		if in.Recovery && cfg.LastRecovery == "" {
			return errV2Unavailable
		}
		if !in.Recovery {
			op, err := r.lookup(state, in.Subject, in.Operation)
			if err != nil {
				return err
			}
			if (op.State != "pending" && op.State != "uncertain") || op.Domain != in.Domain || op.Request.Kind != in.Kind {
				return errV2Unavailable
			}
		}
	}
	if cfg.Pending != nil {
		p := cfg.Pending
		op, err := r.lookup(state, p.Owner, p.OriginCommit)
		if err != nil {
			return err
		}
		if op.Domain != p.Domain || (op.Request.Kind != OpCommit && op.Request.Kind != OpRollback) {
			return errV2Unavailable
		}
		if live && (op.State != "final" || !op.Pinned || op.Outcome == nil || op.Outcome.Code != "applied_pending_confirmation") {
			return errV2Unavailable
		}
		if op.Outcome != nil && (op.Outcome.ConfirmationLease != p.Lease || op.Outcome.RunningRevision != p.Target || op.Outcome.ConfirmationDeadline == nil || !op.Outcome.ConfirmationDeadline.Equal(p.Deadline)) {
			// Only a non-live, exact plan target may describe a prospective
			// lease that was compensated before it became a published outcome.
			if live || !reserveCompensatedSnapshotV2(cfg, state, op, r.object) {
				return errV2Unavailable
			}
		}
		if err := r.snapshot(p.Previous, key, state, depth+1); err != nil {
			return err
		}
		var previous v2Configuration
		if err := r.object(p.Previous, &previous); err != nil {
			return err
		}
		if previous.Intent != nil || previous.Pending != nil {
			return errV2Unavailable
		}
	}
	for _, hash := range []string{cfg.LastRecovery, cfg.LastCompletedBoot} {
		if hash != "" {
			var record v2RecoveryRecord
			if err := r.object(hash, &record); err != nil {
				return err
			}
			entry, err := r.findWitness(cfg.RecoveryIndex, checkpointDigest([]byte(record.ID)))
			if err != nil {
				return err
			}
			if entry.Operation != record.ID || entry.Audit != hash {
				return errV2Unavailable
			}
			if hash == cfg.LastCompletedBoot && (record.Kind != v2BootKind || record.State != "final" || !hasFeatureV2(state, v2BootFeature)) {
				return errV2Unavailable
			}
			if record.State == "pending" && (cfg.Intent == nil || !cfg.Intent.Recovery || cfg.Intent.Operation != record.ID || cfg.Intent.Lease != record.Lease || cfg.Intent.OriginCommit != record.Origin) {
				return errV2Unavailable
			}
			if record.Kind == v2BootKind && (!hasFeatureV2(state, v2BootFeature) || (record.State == "pending" && (cfg.Intent.Kind != v2BootKind || cfg.Intent.BootID == nil || *cfg.Intent.BootID != *record.BootID))) {
				return errV2Unavailable
			}
			if err := r.recovery(hash, "", key, view, depth+1); err != nil {
				return err
			}
		}
	}
	if live {
		for _, ns := range state.Namespaces {
			for _, id := range ns.Open {
				op, err := r.lookup(state, ns.Subject, id)
				if err != nil {
					return err
				}
				switch op.State {
				case "accepted":
				case "pending", "uncertain":
					if cfg.Intent == nil || cfg.Intent.Recovery || cfg.Intent.Operation != op.ID || cfg.Intent.Subject != op.Subject {
						return errV2Unavailable
					}
				case "final":
					if (!op.Pinned || cfg.Pending == nil || cfg.Pending.OriginCommit != op.ID || cfg.Pending.Owner != op.Subject) && !boundaryRetainsOriginV2(state, op) {
						return errV2Unavailable
					}
				default:
					return errV2Unavailable
				}
			}
		}
	}
	return nil
}

func (r *v2ReachabilityReader) findWitness(hash, revision string) (v2VerifiedEntry, error) {
	if !validHash(revision) {
		return v2VerifiedEntry{}, errV2Unavailable
	}
	prefix := ""
	for depth := 0; depth <= v2VerifiedDepthLimit; depth++ {
		var node v2VerifiedNode
		if err := r.object(hash, &node); err != nil {
			return v2VerifiedEntry{}, err
		}
		if !validVerifiedNodeV2(node, depth, prefix) {
			return v2VerifiedEntry{}, errV2Unavailable
		}
		if node.Kind == "leaf" {
			for _, entry := range node.Entries {
				if entry.Revision == revision {
					return entry, nil
				}
			}
			return v2VerifiedEntry{}, errV2Unavailable
		}
		index := strings.IndexByte("0123456789abcdef", revision[depth])
		if index < 0 {
			return v2VerifiedEntry{}, errV2Unavailable
		}
		hash = node.Children[index]
		prefix += revision[depth : depth+1]
	}
	return v2VerifiedEntry{}, errV2Unavailable
}

func (r *v2ReachabilityReader) snapshot(hash, key string, state v2State, depth int) error {
	if r.cache != nil {
		// The complete state, not a traversal-path label, is the validation context.
		// Keep all fields in the digest so future state fields cannot be omitted.
		_, contextHash, err := v2Canonical(state)
		if err != nil {
			return err
		}
		key = contextHash
	}
	return r.walk("snapshot:"+key+":"+hash, depth, func() error {
		var cfg v2Configuration
		release, err := r.load(hash, &cfg)
		if err != nil {
			return err
		}
		defer release()
		return r.configuration(cfg, checkpointDigest([]byte(key+hash)), state, depth+1, false)
	})
}

func (r *v2ReachabilityReader) canonicalConfig(hash string, schema, depth int) error {
	return r.walk(fmt.Sprintf("config:%d:%s", schema, hash), depth, func() error {
		var cfg Config
		release, err := r.load(hash, &cfg)
		if err != nil {
			return err
		}
		defer release()
		canonical, err := canonicalDomainRevisionV2(cfg, schema == 6)
		if err != nil || cfg.SchemaVersion != schema || canonical.Hash != hash {
			return errV2Unavailable
		}
		return nil
	})
}

func (r *v2ReachabilityReader) composite(hash string, depth int) error {
	return r.walk("composite:"+hash, depth, func() error {
		var cfg v2CompositeConfig
		release, err := r.load(hash, &cfg)
		if err != nil {
			return err
		}
		defer release()
		var canonical v2CompositeRevision
		if cfg.SchemaVersion == 7 {
			canonical, err = resolveRoutedCompositeV1(cfg, func(hash string, value any) error {
				out, ok := value.(*Revision)
				if !ok {
					return errV2Unavailable
				}
				var config Config
				if e := r.object(hash, &config); e != nil {
					return e
				}
				*out = Revision{Hash: hash, Config: config}
				return nil
			})
		} else {
			canonical, err = CanonicalComposite(cfg)
		}
		if err != nil || canonical.Hash != hash {
			return errV2Unavailable
		}
		if err := r.canonicalConfig(cfg.Domains.Firewall.Revision, cfg.Domains.Firewall.Schema, depth+1); err != nil {
			return err
		}
		return r.canonicalConfig(cfg.Domains.LocalServices.Revision, 3, depth+1)
	})
}

func (r *v2ReachabilityReader) auditChain(hash string, sequence, generation uint64, depth int) error {
	if r.action != nil {
		return r.actionAuditLeafV2(hash, sequence, generation, depth)
	}
	var pending []string
	for hash != "" {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		if depth > r.budget.Depth {
			return errV2InspectionBudget
		}
		if depth > r.report.MaximumDepth {
			r.report.MaximumDepth = depth
		}
		key := fmt.Sprintf("audit:%s:%d:%d", hash, sequence, generation)
		if r.edges[key] == 2 {
			sequence = 0
			break
		}
		if r.edges[key] == 1 {
			return errV2Unavailable
		}
		if r.report.Edges >= r.budget.Edges || uint64(len(r.edges)) >= r.budget.Edges {
			return errV2InspectionBudget
		}
		r.edges[key] = 1
		r.report.Edges++
		pending = append(pending, key)
		var audit v2CoordinatorAudit
		release, err := r.load(hash, &audit)
		if err != nil {
			return err
		}
		valid := audit.Format == v2Format && audit.Sequence == sequence && sequence > 0 && audit.Generation > 0 && audit.Generation <= generation && validHash(audit.Running) && validHash(audit.Startup) && audit.Operation != "" && !audit.At.IsZero() && (audit.Previous == "") == (sequence == 1)
		release()
		if !valid {
			return errV2Unavailable
		}
		hash = audit.Previous
		sequence--
	}
	if sequence != 0 {
		return errV2Unavailable
	}
	for _, key := range pending {
		r.edges[key] = 2
	}
	return nil
}

func (r *v2ReachabilityReader) witness(hash string, level int, prefix string, recovery bool, key string, state v2State, depth int) error {
	return r.walk(fmt.Sprintf("witness:%t:%s:%s:%d:%s", recovery, key, hash, level, prefix), depth, func() error {
		var node v2VerifiedNode
		release, err := r.load(hash, &node)
		if err != nil {
			return err
		}
		defer release()
		if !validVerifiedNodeV2(node, level, prefix) {
			return errV2Unavailable
		}
		if node.Kind == "branch" {
			for i, child := range node.Children {
				if child != "" {
					if err := r.witness(child, level+1, prefix+fmt.Sprintf("%x", i), recovery, key, state, depth+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for _, entry := range node.Entries {
			if recovery {
				if err := r.recovery(entry.Audit, entry.Operation, key, state, depth+1); err != nil {
					return err
				}
				var record v2RecoveryRecord
				if err := r.object(entry.Audit, &record); err != nil {
					return err
				}
				if entry.Revision != checkpointDigest([]byte(record.ID)) {
					return errV2Unavailable
				}
				continue
			}
			var audit v2CoordinatorAudit
			if err := r.object(entry.Audit, &audit); err != nil {
				return err
			}
			if audit.Format != v2Format || audit.Operation != entry.Operation || audit.Running != entry.Revision || (audit.Result != "verified" && audit.Result != "applied") || audit.Generation > state.Generation || state.Configuration == nil || audit.Sequence > state.Configuration.AuditSequence {
				return errV2Unavailable
			}
			if err := r.auditChain(entry.Audit, audit.Sequence, state.Generation, depth+1); err != nil {
				return err
			}
			if err := r.composite(entry.Revision, depth+1); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *v2ReachabilityReader) recovery(hash, id, key string, state v2State, depth int) error {
	return r.recoveryWithOrigin(hash, id, key, state, depth, nil)
}
func (r *v2ReachabilityReader) recoveryWithOrigin(hash, id, key string, state v2State, depth int, archived *v2Operation) error {
	if r.cache != nil {
		contextKey, err := selectedValidationKeyV2(struct {
			State    v2State
			Archived *v2Operation
		}{state, archived})
		if err != nil {
			return err
		}
		key = contextKey
	}
	return r.walk("recovery:"+key+":"+id+":"+hash, depth, func() error {
		var record v2RecoveryRecord
		release, err := r.load(hash, &record)
		if err != nil {
			return err
		}
		defer release()
		if !validRecoveryRecordV2(record, state.Lineage) || (id != "" && record.ID != id) {
			return errV2Unavailable
		}
		if record.SupersededBy != "" {
			if !hasFeatureV2(state, v2RoutedBootBoundaryFeature) || validateRoutedBootSupersessionV2(record, state.Lineage, r.object) != nil {
				return errV2Unavailable
			}
			if err := r.routedBootBoundary(record.BootBoundary, key, state, depth+1); err != nil {
				return err
			}
		}
		for _, snapshot := range []string{record.Previous, record.Target} {
			if record.SupersededBy != "" && snapshot == record.Previous {
				continue
			}
			if err := r.snapshot(snapshot, key, state, depth+1); err != nil {
				return err
			}
		}
		if record.Audit != "" {
			var audit v2CoordinatorAudit
			if err := r.object(record.Audit, &audit); err != nil {
				return err
			}
			if audit.Operation != record.ID || audit.Kind != record.Kind {
				return errV2Unavailable
			}
			if record.Kind == v2BootKind && record.State == "final" && record.SupersededBy == "" {
				var previous, target v2Configuration
				if err := r.object(record.Previous, &previous); err != nil {
					return err
				}
				if err := r.object(record.Target, &target); err != nil {
					return err
				}
				if !r.selectedPureV2("boot-target:"+record.Previous+":"+record.Target, func() bool { return validBootTargetV2(previous, target) }) || audit.Result != "verified" || audit.Subject != "system" || audit.OriginCommit != "" || audit.Lease != "" || state.Configuration == nil || audit.Sequence > state.Configuration.AuditSequence || !audit.At.Equal(*record.Completed) || audit.Running != target.Running.Hash || audit.Startup != target.Startup.Hash {
					return errV2Unavailable
				}
			}
			if err := r.auditChain(record.Audit, audit.Sequence, state.Generation, depth+1); err != nil {
				return err
			}
		}
		if record.Kind != v2BootKind {
			var op v2Operation
			if archived != nil {
				op = *archived
				if op.Subject != record.Subject || op.ID != record.Origin || op.Lineage != state.Lineage {
					return errV2Unavailable
				}
			} else {
				var err error
				op, err = r.lookup(state, record.Subject, record.Origin)
				if err != nil {
					return err
				}
			}
			if op.Outcome == nil || op.Outcome.ConfirmationLease != record.Lease {
				return errV2Unavailable
			}
		}
		return nil
	})
}
