package configpoc

import "time"

func validRecoveryRecordV2(record v2RecoveryRecord, lineage string) bool {
	if record.Format != v2Format || record.ID == "" || len(record.ID) > 128 || record.Lineage != lineage || record.Started.IsZero() || !validHash(record.Previous) || !validHash(record.Target) {
		return false
	}
	if record.Kind == v2BootKind {
		if record.BootID == nil || !validBootIDV2(*record.BootID) || record.Subject != "" || record.Origin != "" || record.Lease != "" {
			return false
		}
	} else if record.Kind == "boot_boundary" {
		if record.BootID == nil || !validBootIDV2(*record.BootID) || record.Subject == "" || len(record.Subject) > 128 || record.Origin == "" || record.Lease == "" || record.State != "final" || record.BootBoundary == nil {
			return false
		}
	} else if record.BootID != nil || record.Subject == "" || len(record.Subject) > 128 || record.Origin == "" || record.Lease == "" || (record.Kind != "timeout" && record.Kind != "restart") {
		return false
	}
	if record.BootBoundary != nil || record.SupersededBy != "" {
		if (record.Kind != v2BootKind && record.Kind != "boot_boundary") || record.State != "final" || !validHash(record.SupersededBy) || !validRoutedBootBoundaryShapeV2(record.BootBoundary) || record.BootBoundary == nil || record.BootBoundary.CompletedBoot != record.SupersededBy || record.BootBoundary.Resolution != "" {
			return false
		}
	}
	for _, character := range record.ID {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	switch record.State {
	case "pending":
		return record.Pinned && record.Completed == nil && record.RetainUntil == nil && (record.Audit == "" || validHash(record.Audit))
	case "final":
		return !record.Pinned && record.Completed != nil && !record.Completed.Before(record.Started) && record.RetainUntil != nil && !record.RetainUntil.Before(record.Completed.Add(30*24*time.Hour)) && validHash(record.Audit)
	}
	return false
}

func (c *v2Coordinator) recoveryIndexPut(root string, record v2RecoveryRecord, hash string) (string, error) {
	if !validRecoveryRecordV2(record, c.store.state.Lineage) || !validHash(hash) {
		return "", errV2Invalid
	}
	return c.cowIndexInsert(root, 0, v2VerifiedEntry{Revision: checkpointDigest([]byte(record.ID)), Audit: hash, Operation: record.ID}, true)
}

func (c *v2Coordinator) recoveryLookupLocked(id string) (v2RecoveryRecord, error) {
	if id == "" || len(id) > 128 {
		return v2RecoveryRecord{}, errV2NotFound
	}
	state := c.store.state.Configuration
	if state == nil || state.RecoveryIndex == "" {
		return v2RecoveryRecord{}, errV2NotFound
	}
	entry, known, err := c.verifiedLookup(state.RecoveryIndex, checkpointDigest([]byte(id)))
	if err != nil {
		return v2RecoveryRecord{}, err
	}
	if !known || entry.Operation != id {
		return v2RecoveryRecord{}, errV2NotFound
	}
	var record v2RecoveryRecord
	if c.store.readObject(entry.Audit, &record) != nil || !validRecoveryRecordV2(record, c.store.state.Lineage) || record.ID != id {
		c.store.blocked = true
		return v2RecoveryRecord{}, errV2Unavailable
	}
	return record, nil
}

// Internal exact lookup for a future authorized transport; no capability or
// cross-subject permission is exposed. Reading never extends retention.
func (c *v2Coordinator) lookupRecovery(subject, id string) (v2RecoveryRecord, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.store.blocked {
		return v2RecoveryRecord{}, errV2Unavailable
	}
	if !c.store.subject(subject) {
		return v2RecoveryRecord{}, errV2NotFound
	}
	record, err := c.recoveryLookupLocked(id)
	if err != nil {
		return record, err
	}
	if record.Subject != subject {
		return v2RecoveryRecord{}, errV2NotFound
	}
	return record, nil
}

// This predicate does not authorize deletion. Protected audit and configuration
// objects remain retained, and export/acknowledgement is still unavailable.
func recoveryDetailEligibleV2(record v2RecoveryRecord, at time.Time) bool {
	return record.State == "final" && !record.Pinned && record.Completed != nil && record.RetainUntil != nil && !at.Before(*record.RetainUntil)
}
