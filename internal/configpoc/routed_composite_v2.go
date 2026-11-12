package configpoc

import (
	"bytes"
	"encoding/json"
)

// resolveRoutedCompositeV1 checks component payloads through the caller's bounded
// store reader. It does not opt a store in, publish state or activate engines.
func resolveRoutedCompositeV1(config v2CompositeConfig, read func(string, any) error) (v2CompositeRevision, error) {
	domains := config.Domains
	if config.SchemaVersion != 7 || read == nil ||
		(domains.Firewall.Schema != 4 && domains.Firewall.Schema != 6) ||
		domains.LocalServices.Schema != 3 || !validHash(domains.Firewall.Revision) ||
		!validHash(domains.LocalServices.Revision) {
		return v2CompositeRevision{}, ErrInvalid
	}
	if domains.Firewall.Schema == 4 {
		if domains.Network != nil {
			return v2CompositeRevision{}, ErrInvalid
		}
	} else if domains.Network == nil || domains.Network.Schema != 1 || !validHash(domains.Network.Revision) {
		return v2CompositeRevision{}, ErrInvalid
	}
	for _, reference := range []v2ComponentReference{domains.Firewall, domains.LocalServices} {
		var revision Revision
		if err := read(reference.Revision, &revision); err != nil {
			return v2CompositeRevision{}, err
		}
		if revision.Hash != reference.Revision || revision.Config.SchemaVersion != reference.Schema {
			return v2CompositeRevision{}, ErrInvalid
		}
		var canonical Revision
		var err error
		if reference.Schema == 6 {
			canonical, err = CanonicalRouted(revision.Config)
		} else {
			canonical, err = Canonical(revision.Config)
		}
		if err != nil || canonical.Hash != revision.Hash {
			return v2CompositeRevision{}, ErrInvalid
		}
		originalBytes, originalErr := json.Marshal(revision.Config)
		canonicalBytes, canonicalErr := json.Marshal(canonical.Config)
		if originalErr != nil || canonicalErr != nil || !bytes.Equal(originalBytes, canonicalBytes) {
			return v2CompositeRevision{}, ErrInvalid
		}
		if reference.Schema == 6 && canonical.Config.Routed.Network.Hash != domains.Network.Revision {
			return v2CompositeRevision{}, ErrInvalid
		}
	}
	// Detach the optional reference: callers cannot mutate an already hashed view.
	if config.Domains.Network != nil {
		network := *config.Domains.Network
		config.Domains.Network = &network
	}
	data, err := json.Marshal(config)
	if err != nil {
		return v2CompositeRevision{}, ErrInvalid
	}
	return v2CompositeRevision{Hash: checkpointDigest(data), Config: config}, nil
}
