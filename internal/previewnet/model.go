// Package previewnet owns the isolated network fixture of the native preview.
package previewnet

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	RuntimeDir    = "/run/andeiva-preview"
	MetadataPath  = RuntimeDir + "/runtime.json"
	NamespacePath = RuntimeDir + "/netns/gateway"
	ControlPath   = RuntimeDir + "/control.sock"
)

var ErrRuntime = errors.New("ANDEIVA_PREVIEW_NETWORK_UNAVAILABLE")

type Metadata struct {
	SchemaVersion    int    `json:"schema_version"`
	RunID            string `json:"run_id"`
	BootID           string `json:"boot_id"`
	HostNamespace    uint64 `json:"host_namespace"`
	GatewayNamespace uint64 `json:"gateway_namespace"`
	SourceNamespace  uint64 `json:"source_namespace"`
	SinkNamespace    uint64 `json:"sink_namespace"`
}

func (m Metadata) Validate() error {
	id, err := hex.DecodeString(m.RunID)
	if m.SchemaVersion != 1 || err != nil || len(id) != 16 || hex.EncodeToString(id) != m.RunID || !validBootID(m.BootID) {
		return ErrRuntime
	}
	seen := map[uint64]bool{}
	for _, value := range []uint64{m.HostNamespace, m.GatewayNamespace, m.SourceNamespace, m.SinkNamespace} {
		if value == 0 || seen[value] {
			return ErrRuntime
		}
		seen[value] = true
	}
	return nil
}

func validBootID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(value, "-", "")
	b, e := hex.DecodeString(raw)
	return e == nil && len(b) == 16 && hex.EncodeToString(b) == raw
}

type Options struct {
	Executable string
	UID, GID   uint32
	Log        io.Writer
}

type ControlRequest struct {
	Operation string `json:"operation"`
	Protocol  string `json:"protocol,omitempty"`
	Port      int    `json:"port,omitempty"`
}

func (r ControlRequest) Validate() error {
	if r.Operation == "status" && r.Protocol == "" && r.Port == 0 {
		return nil
	}
	if (r.Operation == "probe" || r.Operation == "probe-reverse") && (r.Protocol == "tcp" || r.Protocol == "udp") && r.Port >= 18080 && r.Port <= 18082 {
		return nil
	}
	return ErrRuntime
}

type ControlReply struct {
	Operation string    `json:"operation"`
	At        time.Time `json:"at"`
	RunID     string    `json:"run_id"`
	Healthy   bool      `json:"healthy"`
	Allowed   *bool     `json:"allowed,omitempty"`
	Error     string    `json:"error,omitempty"`
}

type fixture interface {
	NamespaceIDs() map[string]uint64
	SealAdminDeny(context.Context) error
	PinPreviewGateway() error
	StartReverseListener(context.Context) error
	CheckHost(context.Context) error
	CheckSentinel(context.Context) error
	CheckPreviewListeners(context.Context) error
	Probe(context.Context, string, int) (bool, error)
	ProbeReverse(context.Context, string, int) (bool, error)
	Close() error
}
