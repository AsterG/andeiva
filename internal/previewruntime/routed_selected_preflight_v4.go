package previewruntime

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const RoutedSelectedPreflightRoleV4 = "--andeiva-routed-selected-preflight-v4"
const routedPrivateFrameV4 = 1 << 20

type RoutedSelectedPreflightPurposeV4 string

const (
	RoutedPreflightRetirementV4 RoutedSelectedPreflightPurposeV4 = "retirement"
	RoutedPreflightDHCPV4       RoutedSelectedPreflightPurposeV4 = "dhcp"
)

// A result is correlation from a private root-launched reader, not a portable
// capability. The root caller retains its publication barrier through effects.
type RoutedSelectedPreflightResultV4 struct {
	Identity   networkexecutor.OwnedNamespaceIdentity `json:"identity"`
	Reference  configpoc.SelectionReferenceV2         `json:"reference"`
	Work       configpoc.RoutedWorkReferenceV1        `json:"work"`
	Bundle     configpoc.RoutedActivationBundleV1     `json:"bundle"`
	Resolution string                                 `json:"resolution"`
}

type routedSelectedPreflightReplyV4 struct {
	Version int                             `json:"version"`
	Nonce   string                          `json:"nonce"`
	PID     int                             `json:"pid"`
	Start   uint64                          `json:"start,string"`
	Result  RoutedSelectedPreflightResultV4 `json:"result"`
}

// Private peers emit canonical JSON. Re-encoding also rejects case aliases and
// unexpected null/default encodings in legacy nested DTOs with uppercase keys.
func routedPrivateDecodeV4(data []byte, out any) error {
	if len(data) == 0 || len(data) > routedPrivateFrameV4 || !jsoncheck.UniqueFields(data) {
		return ErrIdentity
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrIdentity
	}
	canonical, err := json.Marshal(out)
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, data) != nil || !bytes.Equal(canonical, compact.Bytes()) {
		return ErrIdentity
	}
	return nil
}

func routedPrivateWriteV4(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data)+1 > routedPrivateFrameV4 {
		return ErrIdentity
	}
	data = append(data, '\n')
	n, err := w.Write(data)
	if err != nil || n != len(data) {
		return ErrUnavailable
	}
	return nil
}

func routedPrivateHashV4(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

func routedPreflightResultV4(result RoutedSelectedPreflightResultV4, purpose RoutedSelectedPreflightPurposeV4, identity networkexecutor.OwnedNamespaceIdentity, work configpoc.RoutedWorkReferenceV1) error {
	if result.Identity != identity || !routedPrivateHashV4(result.Reference.Selection) || !routedPrivateHashV4(result.Reference.State) || !routedPrivateHashV4(result.Reference.WorkHash) || result.Reference.Lineage == "" {
		return ErrIdentity
	}
	switch purpose {
	case RoutedPreflightRetirementV4:
		if work != (configpoc.RoutedWorkReferenceV1{}) || result.Work != work || result.Resolution != "" || !reflect.DeepEqual(result.Bundle, configpoc.RoutedActivationBundleV1{}) {
			return ErrIdentity
		}
	case RoutedPreflightDHCPV4:
		if result.Work != work || !routedPrivateHashV4(work.Work) || work.Lineage != result.Reference.Lineage || work.Work != result.Reference.WorkHash || work.Generation == 0 || (result.Resolution != "" && result.Resolution != "target") {
			return ErrIdentity
		}
		canonical, err := configpoc.CanonicalRoutedActivationBundleV1(result.Bundle)
		if err != nil || !reflect.DeepEqual(canonical, result.Bundle) || canonical.Firewall.Config.Routed == nil {
			return ErrIdentity
		}
		if _, err = networkexecutor.CanonicalLANBootstrapPlanV3(canonical.Firewall.Config.Routed.Network); err != nil {
			return ErrIdentity
		}
	default:
		return ErrIdentity
	}
	return nil
}
