// Package localobserve reads kernel socket ownership without changing networking.
package localobserve

import "errors"

const (
	MaxTableBytes    = 256 << 10
	MaxIdentityBytes = 64 << 10
	MaxRows          = 1024
	MaxFDs           = 2048
)

var (
	ErrPlatform  = errors.New("local_observation_platform")
	ErrIdentity  = errors.New("local_observation_identity")
	ErrMalformed = errors.New("local_observation_malformed")
	ErrUnstable  = errors.New("local_observation_unstable")
	ErrOwnership = errors.New("local_observation_ownership")
	ErrClosed    = errors.New("local_observation_closed")
)

// Expected is trusted supervisor state, never a JSON request from an administrator.
type Expected struct {
	UID, GID                 uint32
	Namespace, HostNamespace uint64
	RunID, Instance          string
	Generation               uint64
}

type Socket struct {
	Protocol string `json:"protocol"`
	Family   string `json:"family"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Inode    uint64 `json:"inode"`
	UID      uint32 `json:"uid"`
	Wildcard bool   `json:"wildcard"`
	Mapped   bool   `json:"mapped"`
}

type Snapshot struct {
	RunID      string   `json:"run_id"`
	Instance   string   `json:"instance"`
	Generation uint64   `json:"generation"`
	Namespace  uint64   `json:"namespace"`
	StartTime  uint64   `json:"start_time"`
	Sockets    []Socket `json:"sockets"`
	Foreign    []Socket `json:"foreign"`
}

type processIdentity struct {
	pid, parent int
	start       uint64
	uid, gid    [4]uint32
	namespace   uint64
}
type socketFD struct {
	fd    int
	inode uint64
}
type capture struct {
	identity processIdentity
	sockets  []Socket
	fds      []socketFD
}
