// Package configpoc implements an isolated configuration experiment with simulated engines.
package configpoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sync"
	"time"
)

var (
	ErrInvalid     = errors.New("ANDEIVA_CONFIG_INVALID")
	ErrDenied      = errors.New("ANDEIVA_CONFIG_DENIED")
	ErrConflict    = errors.New("ANDEIVA_CONFIG_CONFLICT")
	ErrReplay      = errors.New("ANDEIVA_CONFIG_REPLAY_CONFLICT")
	ErrStorage     = errors.New("ANDEIVA_CONFIG_STORAGE_UNAVAILABLE")
	ErrRecovery    = errors.New("ANDEIVA_CONFIG_RECOVERY_REQUIRED")
	ErrEngine      = errors.New("ANDEIVA_CONFIG_ENGINE_FAILURE")
	ErrPending     = errors.New("ANDEIVA_CONFIG_CONFIRMATION_PENDING")
	ErrExpired     = errors.New("ANDEIVA_CONFIG_CONFIRMATION_EXPIRED")
	ErrInterrupted = errors.New("ANDEIVA_CONFIG_INTERRUPTED")
	ErrLocked      = errors.New("ANDEIVA_CONFIG_STORE_LOCKED")
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type Surface string

const (
	Web Surface = "web"
	CLI Surface = "cli"
	API Surface = "api"
)
const (
	OpStatus   = "status"
	OpStage    = "stage"
	OpValidate = "validate"
	OpCommit   = "commit"
	OpConfirm  = "confirm"
	OpSave     = "save"
	OpRecover  = "recover"
	OpRevoke   = "revoke"
	OpRollback = "rollback"
)

// Principal is supplied by a trusted adapter, never decoded from a request body.
// This experiment does not authenticate identities or provide transport endpoints.
type Principal struct {
	ID   string
	Role Role
}
type Rule struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Match  *Match `json:"match,omitempty"`
}
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}
type Match struct {
	Source           string    `json:"source"`
	Destination      string    `json:"destination"`
	Protocol         string    `json:"protocol"`
	SourcePorts      PortRange `json:"source_ports"`
	DestinationPorts PortRange `json:"destination_ports"`
}
type Config struct {
	SchemaVersion int    `json:"schema_version"`
	DefaultAction string `json:"default_action"`
	Rules         []Rule `json:"rules"`
}
type Revision struct {
	Hash   string `json:"hash"`
	Config Config `json:"config"`
}
type Candidate struct {
	Owner    string   `json:"owner"`
	Base     string   `json:"base"`
	Revision Revision `json:"revision"`
}
type Pending struct {
	Owner    string    `json:"owner"`
	Previous Revision  `json:"previous"`
	Deadline time.Time `json:"deadline"`
}
type Intent struct {
	Previous Revision `json:"previous"`
	Target   Revision `json:"target"`
}
type Snapshot struct {
	Generation         uint64     `json:"generation"`
	Candidate          *Candidate `json:"candidate,omitempty"`
	Running            Revision   `json:"running"`
	Startup            Revision   `json:"startup"`
	LastGood           Revision   `json:"last_good"`
	Pending            *Pending   `json:"pending,omitempty"`
	RecoveryRequired   bool       `json:"recovery_required"`
	ReplayedGeneration uint64     `json:"replayed_generation,omitempty"`
	Revoked            []string   `json:"revoked"`
}
type Request struct {
	Operation          string        `json:"operation"`
	Key                string        `json:"key"`
	ExpectedGeneration uint64        `json:"expected_generation"`
	Config             *Config       `json:"config,omitempty"`
	ConfirmFor         time.Duration `json:"confirm_for,omitempty"`
	Target             string        `json:"target,omitempty"`
}
type Audit struct {
	Sequence    uint64    `json:"sequence"`
	At          time.Time `json:"at"`
	Actor       string    `json:"actor"`
	Surface     Surface   `json:"surface"`
	Operation   string    `json:"operation"`
	Result      string    `json:"result"`
	RunningHash string    `json:"running_hash"`
}
type Engine interface {
	Name() string
	Validate(Config) error
	Apply(context.Context, Revision) error
	Current() string
}
type Options struct {
	// Initial applies only to a new empty store. Existing journals retain their schema.
	Initial *Config
	// Boot explicitly models appliance boot; ordinary Open models a controller restart.
	Boot       bool
	MaxRecords int
	// Hook is a test fault boundary, not an extension point for untrusted callers.
	Hook func(string) error
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func Canonical(config Config) (Revision, error) {
	if (config.SchemaVersion != 1 && config.SchemaVersion != 2) || config.DefaultAction != "deny" || len(config.Rules) > 64 {
		return Revision{}, ErrInvalid
	}
	seen := make(map[string]bool)
	for _, rule := range config.Rules {
		if config.SchemaVersion == 1 && rule.Match != nil || config.SchemaVersion == 2 && !validMatch(rule.Match) {
			return Revision{}, ErrInvalid
		}
		if !identifier.MatchString(rule.ID) || seen[rule.ID] || (rule.Action != "allow" && rule.Action != "deny") {
			return Revision{}, ErrInvalid
		}
		seen[rule.ID] = true
	}
	config.Rules = clone(append([]Rule{}, config.Rules...))
	data, err := json.Marshal(config)
	if err != nil {
		return Revision{}, ErrInvalid
	}
	hash := sha256.Sum256(data)
	return Revision{hex.EncodeToString(hash[:]), config}, nil
}
func validMatch(m *Match) bool {
	if m == nil || (m.Protocol != "tcp" && m.Protocol != "udp") {
		return false
	}
	for _, s := range []string{m.Source, m.Destination} {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != s {
			return false
		}
	}
	for _, p := range []PortRange{m.SourcePorts, m.DestinationPorts} {
		if p.From == 0 || p.To < p.From {
			return false
		}
	}
	return true
}
func clone[T any](value T) T {
	data, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(data, &out)
	return out
}

// SimEngine stores only a revision hash. It never invokes a process or changes traffic.
type SimEngine struct {
	mu                              sync.Mutex
	name, current, phase, faultHash string
	once                            bool
}

func NewSimEngine(name string) *SimEngine    { return &SimEngine{name: name} }
func (e *SimEngine) Name() string            { return e.name }
func (e *SimEngine) Validate(c Config) error { _, err := Canonical(c); return err }
func (e *SimEngine) Current() string         { e.mu.Lock(); defer e.mu.Unlock(); return e.current }
func (e *SimEngine) FailNext(phase string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.phase = phase
	e.faultHash = ""
	e.once = true
}
func (e *SimEngine) SetFailure(hash, phase string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.faultHash = hash
	e.phase = phase
	e.once = false
}
func (e *SimEngine) ClearFailure()     { e.mu.Lock(); defer e.mu.Unlock(); e.phase = ""; e.faultHash = "" }
func (e *SimEngine) Drift(hash string) { e.mu.Lock(); defer e.mu.Unlock(); e.current = hash }
func (e *SimEngine) Apply(ctx context.Context, revision Revision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	fault := e.phase != "" && (e.faultHash == "" || e.faultHash == revision.Hash)
	phase := e.phase
	if fault && e.once {
		e.phase = ""
	}
	if fault && phase == "before" {
		return ErrEngine
	}
	e.current = revision.Hash
	if fault && phase == "after" {
		return ErrEngine
	}
	return nil
}
