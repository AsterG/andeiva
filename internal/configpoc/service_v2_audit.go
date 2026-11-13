package configpoc

import (
	"context"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

const auditScanV2 = 1024
const auditBytesV2 = 2 << 20
const auditRecordBytesV2 = 16 << 10

// AuditEventV2 exposes administrative facts without private runtime diagnostics.
// ActorName is the current registry name; ActorID preserves durable identity.
type AuditEventV2 struct {
	Sequence    uint64    `json:"sequence,string"`
	At          time.Time `json:"at"`
	ActorID     string    `json:"actor_id"`
	ActorName   string    `json:"actor_name,omitempty"`
	OperationID string    `json:"operation_id"`
	Operation   string    `json:"operation"`
	Result      string    `json:"result"`
	Generation  uint64    `json:"generation,string"`
	Running     string    `json:"running_revision"`
	Startup     string    `json:"startup_revision"`
}

type AuditPageV2 struct {
	SchemaVersion int            `json:"schema_version"`
	Events        []AuditEventV2 `json:"events"`
	NextBefore    uint64         `json:"next_before,string"`
	Truncated     bool           `json:"truncated"`
}

// AuditV2 follows only the selected protected chain. Pagination is exclusive and
// subject to fixed I/O/work limits; an arbitrary object hash is never a cursor.
func (s *ServiceV2) AuditV2(ctx context.Context, binding adminauth.SessionBinding, before uint64, limit int) (AuditPageV2, error) {
	if ctx == nil || limit < 1 || limit > 100 {
		return AuditPageV2{}, ErrInvalid
	}
	p, err := s.principal(binding)
	if err != nil {
		return AuditPageV2{}, err
	}
	if p.Role != RoleAdmin {
		return AuditPageV2{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c := s.coordinator
	for !c.store.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return AuditPageV2{}, ctx.Err()
		case <-timer.C:
		}
	}
	defer c.store.mu.Unlock()
	if ctx.Err() != nil {
		return AuditPageV2{}, ctx.Err()
	}
	if c.closed || c.store.blocked || c.store.state.Configuration == nil {
		return AuditPageV2{}, errV2Unavailable
	}
	if !c.store.principalV2Locked(p) {
		return AuditPageV2{}, ErrDenied
	}
	state := c.store.state.Configuration
	page := AuditPageV2{SchemaVersion: 1, Events: []AuditEventV2{}}
	if before > state.AuditSequence && before-state.AuditSequence > 1 {
		return AuditPageV2{}, ErrInvalid
	}
	hash, sequence, remaining := state.AuditTip, state.AuditSequence, auditBytesV2
	seen := map[string]bool{}
	for scanned := 0; hash != ""; scanned++ {
		if ctx.Err() != nil {
			return AuditPageV2{}, ctx.Err()
		}
		if scanned >= auditScanV2 || remaining < auditRecordBytesV2 {
			page.Truncated = true
			break
		}
		if seen[hash] {
			c.store.blocked = true
			return AuditPageV2{}, errV2Unavailable
		}
		seen[hash] = true
		name, err := v2ObjectName(hash)
		if err != nil {
			c.store.blocked = true
			return AuditPageV2{}, errV2Unavailable
		}
		data, err := c.store.readRecordV2(name, auditRecordBytesV2)
		remaining -= len(data)
		var record v2CoordinatorAudit
		if err != nil || checkpointDigest(data) != hash || checkpointDecode(data, &record) != nil || record.Format != v2Format || record.Sequence != sequence || sequence == 0 || record.At.IsZero() || record.Generation == 0 || record.Generation > c.store.state.Generation || !validHash(record.Running) || !validHash(record.Startup) || !clientAuditIDV2(record.Subject) || !clientAuditIDV2(record.Operation) || !clientAuditIDV2(record.Kind) || !clientAuditIDV2(record.Result) || (sequence == 1) != (record.Previous == "") {
			c.store.blocked = true
			return AuditPageV2{}, errV2Unavailable
		}
		if before == 0 || sequence < before {
			event := AuditEventV2{Sequence: sequence, At: record.At, ActorID: record.Subject, OperationID: record.Operation, Operation: record.Kind, Result: record.Result, Generation: record.Generation, Running: record.Running, Startup: record.Startup}
			for _, subject := range c.store.state.Subjects {
				if subject.ID == record.Subject {
					event.ActorName = subject.Login
					break
				}
			}
			page.Events = append(page.Events, event)
			if len(page.Events) == limit {
				if record.Previous != "" {
					page.NextBefore = sequence
				}
				return page, nil
			}
		}
		hash, sequence = record.Previous, sequence-1
	}
	return page, nil
}

func clientAuditIDV2(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
