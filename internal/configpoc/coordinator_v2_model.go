package configpoc

import (
	"encoding/json"
	"time"
)

type v2CompositeDomains struct {
	Firewall      v2ComponentReference  `json:"firewall"`
	LocalServices v2ComponentReference  `json:"local_services"`
	Network       *v2ComponentReference `json:"network"`
}
type v2CompositeConfig struct {
	SchemaVersion int                `json:"schema_version"`
	Domains       v2CompositeDomains `json:"domains"`
}
type v2CompositeRevision struct {
	Hash   string            `json:"hash"`
	Config v2CompositeConfig `json:"config"`
}

// CanonicalComposite hashes the composite reference document without changing
// the canonical component schemas, payloads or their existing revision hashes.
func CanonicalComposite(config v2CompositeConfig) (v2CompositeRevision, error) {
	if config.SchemaVersion != 5 || config.Domains.Network != nil || config.Domains.Firewall.Schema != 4 || config.Domains.LocalServices.Schema != 3 || !validHash(config.Domains.Firewall.Revision) || !validHash(config.Domains.LocalServices.Revision) {
		return v2CompositeRevision{}, ErrInvalid
	}
	data, err := json.Marshal(config)
	if err != nil {
		return v2CompositeRevision{}, ErrInvalid
	}
	return v2CompositeRevision{Hash: checkpointDigest(data), Config: config}, nil
}

type v2DomainCandidate struct {
	Owner    string   `json:"owner"`
	Base     string   `json:"base"`
	Revision Revision `json:"revision"`
}
type v2DomainSnapshot struct {
	Generation uint64             `json:"generation,string"`
	Candidate  *v2DomainCandidate `json:"candidate,omitempty"`
	Running    Revision           `json:"running"`
	Startup    Revision           `json:"startup"`
	LastGood   Revision           `json:"last_good"`
}
type v2Confirmation struct {
	OriginCommit string    `json:"origin_commit_operation_id"`
	Lease        string    `json:"lease"`
	Owner        string    `json:"owner"`
	Domain       string    `json:"domain"`
	Previous     string    `json:"previous_snapshot"`
	Target       string    `json:"target_revision"`
	Deadline     time.Time `json:"deadline"`
}
type v2CoordinatorIntent struct {
	DHCPWork         string     `json:"dhcp_work,omitempty"`
	RoutedWork       string     `json:"routed_work,omitempty"`
	GuardDeadline    *time.Time `json:"guard_deadline,omitempty"`
	BootID           *v2BootID  `json:"boot_id,omitempty"`
	Operation        string     `json:"operation_id"`
	Subject          string     `json:"subject"`
	Domain           string     `json:"domain"`
	Kind             string     `json:"kind"`
	Previous         string     `json:"previous_snapshot"`
	Target           string     `json:"target_snapshot"`
	TargetGeneration uint64     `json:"target_generation,string"`
	Recovery         bool       `json:"recovery"`
	OriginCommit     string     `json:"origin_commit_operation_id,omitempty"`
	Lease            string     `json:"lease,omitempty"`
}
type v2Configuration struct {
	CandidateGroup    *v2CandidateGroup    `json:"candidate_group,omitempty"`
	LastCompletedBoot string               `json:"last_completed_boot,omitempty"`
	Firewall          v2DomainSnapshot     `json:"firewall"`
	LocalServices     v2DomainSnapshot     `json:"local_services"`
	Running           v2CompositeRevision  `json:"running"`
	Startup           v2CompositeRevision  `json:"startup"`
	LastGood          v2CompositeRevision  `json:"last_good"`
	Candidate         *v2CompositeRevision `json:"candidate,omitempty"`
	Pending           *v2Confirmation      `json:"pending,omitempty"`
	Intent            *v2CoordinatorIntent `json:"intent,omitempty"`
	RecoveryRequired  bool                 `json:"recovery_required"`
	AuditSequence     uint64               `json:"audit_sequence,string"`
	AuditTip          string               `json:"audit_tip,omitempty"`
	LastRecovery      string               `json:"last_recovery,omitempty"`
	VerifiedIndex     string               `json:"verified_index,omitempty"`
	RecoveryIndex     string               `json:"recovery_index,omitempty"`
}
type v2CoordinatorAudit struct {
	Format       string    `json:"format"`
	Sequence     uint64    `json:"sequence,string"`
	Previous     string    `json:"previous"`
	Operation    string    `json:"operation_id"`
	OriginCommit string    `json:"origin_commit_operation_id,omitempty"`
	Lease        string    `json:"lease,omitempty"`
	Subject      string    `json:"subject"`
	Kind         string    `json:"kind"`
	Result       string    `json:"result"`
	At           time.Time `json:"at"`
	Generation   uint64    `json:"generation,string"`
	Running      string    `json:"running_revision"`
	Startup      string    `json:"startup_revision"`
}
type v2RecoveryRecord struct {
	ServiceRestart *v3RoutedServiceRestart `json:"service_restart,omitempty"`
	BootBoundary   *v2RoutedBootBoundary   `json:"boot_boundary,omitempty"`
	SupersededBy   string                  `json:"superseded_by_boot,omitempty"`
	Reserve        *v2ReserveBundle        `json:"reserve,omitempty"`
	BootID         *v2BootID               `json:"boot_id,omitempty"`
	Format         string                  `json:"format"`
	ID             string                  `json:"id"`
	Origin         string                  `json:"origin_commit_operation_id"`
	Lease          string                  `json:"lease"`
	Kind           string                  `json:"kind"`
	State          string                  `json:"state"`
	Previous       string                  `json:"previous_snapshot"`
	Target         string                  `json:"target_snapshot"`
	Audit          string                  `json:"audit_hash,omitempty"`
	Subject        string                  `json:"subject"`
	Lineage        string                  `json:"lineage"`
	Started        time.Time               `json:"started_at"`
	Completed      *time.Time              `json:"completed_at,omitempty"`
	RetainUntil    *time.Time              `json:"retain_until,omitempty"`
	Pinned         bool                    `json:"pinned"`
}

// A trusted transport must verify the durable subject incarnation. Usernames,
// headers, request bodies and current OS UIDs are not identity substitutes.
type v2TrustedPrincipal struct {
	Subject            string
	Role               Role
	Login              string
	CredentialRevision string
}
type v2CoordinatorResult struct {
	Operation        v2Operation
	Current          v2Configuration
	GlobalGeneration uint64
}

func v2CompositeFromDomains(firewall, local Revision) (v2CompositeRevision, error) {
	return CanonicalComposite(v2CompositeConfig{SchemaVersion: 5, Domains: v2CompositeDomains{Firewall: v2ComponentReference{Schema: 4, Revision: firewall.Hash}, LocalServices: v2ComponentReference{Schema: 3, Revision: local.Hash}}})
}

func (state *v2Configuration) refresh() error {
	var err error
	compose := v2CompositeFromDomains
	if state.Running.Config.SchemaVersion == 7 {
		compose = routedCompositeFromDomainsV2
	}
	state.Running, err = compose(state.Firewall.Running, state.LocalServices.Running)
	if err != nil {
		return err
	}
	state.Startup, err = compose(state.Firewall.Startup, state.LocalServices.Startup)
	if err != nil {
		return err
	}
	state.LastGood, err = compose(state.Firewall.LastGood, state.LocalServices.LastGood)
	if err != nil {
		return err
	}
	state.Candidate = nil
	if state.Firewall.Candidate != nil || state.LocalServices.Candidate != nil {
		firewall, local := state.Firewall.Running, state.LocalServices.Running
		if state.Firewall.Candidate != nil {
			firewall = state.Firewall.Candidate.Revision
		}
		if state.LocalServices.Candidate != nil {
			local = state.LocalServices.Candidate.Revision
		}
		revision, e := compose(firewall, local)
		if e != nil {
			return e
		}
		state.Candidate = &revision
	}
	return nil
}

func validV2Configuration(state *v2Configuration) bool {
	if state != nil && state.Intent != nil && state.Intent.DHCPWork != "" {
		return false
	}
	if state == nil {
		return false
	}
	routed := state.Running.Config.SchemaVersion == 7
	if !validCandidateGroupV2(state, routed) {
		return false
	}
	for index, domain := range []v2DomainSnapshot{state.Firewall, state.LocalServices} {
		if domain.Generation == 0 {
			return false
		}
		schema := 4
		if index == 1 {
			schema = 3
		}
		revisions := []Revision{domain.Running, domain.Startup, domain.LastGood}
		if domain.Candidate != nil {
			if domain.Candidate.Owner == "" || len(domain.Candidate.Owner) > 128 || !validHash(domain.Candidate.Base) {
				return false
			}
			revisions = append(revisions, domain.Candidate.Revision)
		}
		for _, revision := range revisions {
			canonical, err := canonicalDomainRevisionV2(revision.Config, routed && index == 0)
			if err != nil || (revision.Config.SchemaVersion != schema && !(routed && index == 0 && revision.Config.SchemaVersion == 6)) || revision.Hash != canonical.Hash {
				return false
			}
		}
	}
	copy := clone(*state)
	if copy.refresh() != nil {
		return false
	}
	if copy.Running.Hash != state.Running.Hash || copy.Startup.Hash != state.Startup.Hash || copy.LastGood.Hash != state.LastGood.Hash || (copy.Candidate == nil) != (state.Candidate == nil) {
		return false
	}
	if copy.Candidate != nil && copy.Candidate.Hash != state.Candidate.Hash {
		return false
	}
	if state.Candidate != nil {
		canonical, err := compositeFromConfigurationV2(state.Candidate.Config, state)
		if err != nil || canonical.Hash != state.Candidate.Hash {
			return false
		}
	}
	for _, revision := range []v2CompositeRevision{state.Running, state.Startup, state.LastGood} {
		canonical, err := compositeFromConfigurationV2(revision.Config, state)
		if err != nil || canonical.Hash != revision.Hash {
			return false
		}
	}
	if state.AuditTip != "" && !validHash(state.AuditTip) {
		return false
	}
	if (state.AuditSequence == 0) != (state.AuditTip == "") {
		return false
	}
	if state.LastRecovery != "" && !validHash(state.LastRecovery) {
		return false
	}
	if state.LastCompletedBoot != "" && !validHash(state.LastCompletedBoot) {
		return false
	}
	if state.VerifiedIndex != "" && !validHash(state.VerifiedIndex) {
		return false
	}
	if state.RecoveryIndex != "" && !validHash(state.RecoveryIndex) {
		return false
	}
	if pending := state.Pending; pending != nil {
		if !configurationDomainV2(pending.Domain, routed) || pending.Owner == "" || pending.OriginCommit == "" || pending.Lease == "" || !validHash(pending.Previous) || pending.Target != state.Running.Hash || pending.Deadline.IsZero() {
			return false
		}
	}
	if intent := state.Intent; intent != nil {
		if intent.RoutedWork != "" && (!routed || intent.Domain != "routed" || !validHash(intent.RoutedWork)) {
			return false
		}
		if !validGuardDeadlineShapeV2(intent) {
			return false
		}
		if intent.Operation == "" || !configurationDomainV2(intent.Domain, routed) || !validHash(intent.Previous) || !validHash(intent.Target) || intent.TargetGeneration == 0 {
			return false
		}
		if intent.Kind == v2BootKind {
			if !validBootIntentV2(intent) {
				return false
			}
		} else if intent.BootID != nil || intent.Subject == "" {
			return false
		}
	}
	return true
}
