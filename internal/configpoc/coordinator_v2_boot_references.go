package configpoc

func (c *v2Coordinator) validateCompletedBootLocked(hash string) error {
	var record v2RecoveryRecord
	if c.store.readObject(hash, &record) != nil || !validRecoveryRecordV2(record, c.store.state.Lineage) || record.Kind != v2BootKind || record.State != "final" {
		return errV2Unavailable
	}
	indexed, err := c.recoveryLookupLocked(record.ID)
	if err != nil || indexed.Audit != record.Audit || indexed.State != "final" || indexed.BootID == nil || *indexed.BootID != *record.BootID {
		return errV2Unavailable
	}
	var target v2Configuration
	var audit v2CoordinatorAudit
	if c.store.readObject(record.Target, &target) != nil || !validV2Configuration(&target) || c.store.readObject(record.Audit, &audit) != nil || audit.Operation != record.ID || audit.Kind != v2BootKind || audit.Result != "verified" || audit.Subject != "system" || audit.OriginCommit != "" || audit.Lease != "" || audit.Generation > c.store.state.Generation || audit.Sequence > c.store.state.Configuration.AuditSequence || audit.Running != target.Running.Hash || audit.Startup != target.Startup.Hash {
		return errV2Unavailable
	}
	return nil
}
