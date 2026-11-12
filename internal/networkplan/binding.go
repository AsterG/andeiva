package networkplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"

	"github.com/AsterG/andeiva/internal/networkinventory"
)

type BindingReport struct {
	Revision      string            `json:"revision"`
	InventoryHash string            `json:"inventory_hash"`
	Interfaces    []ResolvedBinding `json:"interfaces"`
	RequiredDHCP  []string          `json:"required_dhcp"`
}

type ResolvedBinding struct {
	InterfaceID     string `json:"interface_id"`
	Name            string `json:"name"`
	Index           int    `json:"index"`
	HardwareAddress string `json:"hardware_address"`
}

// Bind checks a trusted inventory, never a caller-supplied inventory body. The
// hash binds this observation only; it is neither an atomic kernel snapshot nor
// authentication. An executor must recheck before effects and after application.
// Observed IP addresses are deliberately not treated as verified DHCP leases.
func Bind(revision Revision, observed networkinventory.Snapshot) (BindingReport, error) {
	canonical, err := Canonical(revision.Config)
	if err != nil || revision.Hash != canonical.Hash || observed.SchemaVersion != networkinventory.SchemaVersion || len(observed.Interfaces) > networkinventory.MaxInterfaces {
		return BindingReport{}, invalid("OBSERVATION", "inventory")
	}
	byName := make(map[string]networkinventory.Interface, len(observed.Interfaces))
	indexes := make(map[int]bool, len(observed.Interfaces))
	for _, iface := range observed.Interfaces {
		if _, duplicate := byName[iface.Name]; duplicate || iface.Index <= 0 || iface.Index > math.MaxInt32 || indexes[iface.Index] || len(iface.Name) > networkinventory.MaxNameBytes || len(iface.HardwareAddress) > 64 || len(iface.Addresses) > networkinventory.MaxAddresses {
			return BindingReport{}, invalid("OBSERVATION", "inventory")
		}
		byName[iface.Name], indexes[iface.Index] = iface, true
	}
	report := BindingReport{Revision: canonical.Hash, Interfaces: []ResolvedBinding{}, RequiredDHCP: []string{}}
	for _, desired := range canonical.Config.Interfaces {
		actual, found := byName[desired.Binding.Name]
		if !found || actual.Kind == networkinventory.Loopback || actual.PointToPoint {
			return BindingReport{}, invalid("BINDING_CHANGED", "interfaces.binding")
		}
		mac, err := net.ParseMAC(actual.HardwareAddress)
		if err != nil || mac.String() != desired.Binding.HardwareAddress {
			return BindingReport{}, invalid("BINDING_CHANGED", "interfaces.binding.hardware_address")
		}
		report.Interfaces = append(report.Interfaces, ResolvedBinding{InterfaceID: desired.ID, Name: actual.Name, Index: actual.Index, HardwareAddress: mac.String()})
		if desired.IPv4.Mode == "dhcp" {
			report.RequiredDHCP = append(report.RequiredDHCP, desired.ID)
		}
	}
	// Inventory is captured by the existing stateless collector; no device or OS
	// version is included in its observation. Preserve the full trusted sample.
	encoded, err := json.Marshal(observed)
	if err != nil {
		return BindingReport{}, invalid("OBSERVATION", "inventory")
	}
	hash := sha256.Sum256(encoded)
	report.InventoryHash = hex.EncodeToString(hash[:])
	return report, nil
}
