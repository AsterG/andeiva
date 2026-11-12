// Package routedactivation assembles the laboratory's owned routed components.
// It grants no host, durable-plan or public-request authority.
package routedactivation

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/AsterG/andeiva/internal/configpoc"
)

const MaxArtifact = configpoc.RoutedArtifactLimit

var ErrState = configpoc.ErrRoutedArtifact

type Presence = configpoc.Presence

const (
	Absent  = configpoc.Absent
	Present = configpoc.Present
)

type NetworkState = configpoc.NetworkState

const (
	Baseline   = configpoc.Baseline
	Configured = configpoc.Configured
	NoNetwork  = configpoc.NoNetwork
)

type TableStateV1 = configpoc.TableStateV1
type OwnedV1 = configpoc.OwnedV1
type DependenciesV1 = configpoc.DependenciesV1

func canonicalTable(input TableStateV1, schema int) (TableStateV1, error) {
	return configpoc.CanonicalRoutedTable(input, schema)
}
func CanonicalOwned(input OwnedV1) (OwnedV1, error) { return configpoc.CanonicalOwned(input) }
func CanonicalDependencies(input DependenciesV1) (DependenciesV1, error) {
	return configpoc.CanonicalDependencies(input)
}
func OwnedBytes(input OwnedV1) ([]byte, error) { return configpoc.OwnedBytes(input) }
func DependenciesBytes(input DependenciesV1) ([]byte, error) {
	return configpoc.DependenciesBytes(input)
}
func artifactDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
