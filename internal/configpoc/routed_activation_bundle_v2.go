package configpoc

import "encoding/json"

// CompositeRevisionV1 is the reference document shared by trusted activation
// components. Its validity still requires resolving its component payloads.
type CompositeRevisionV1 = v2CompositeRevision

type RoutedActivationBundleV1 struct {
	Version       int                 `json:"version"`
	Composite     CompositeRevisionV1 `json:"composite"`
	Firewall      Revision            `json:"firewall"`
	LocalServices Revision            `json:"local_services"`
}

// NewRoutedActivationBundleV1 builds one typed activation unit. It grants no
// authority to apply it; the coordinator and helper must bind its durable scope.
func NewRoutedActivationBundleV1(firewall, local Revision) (RoutedActivationBundleV1, error) {
	doc := v2CompositeConfig{SchemaVersion: 7, Domains: v2CompositeDomains{
		Firewall:      v2ComponentReference{Schema: firewall.Config.SchemaVersion, Revision: firewall.Hash},
		LocalServices: v2ComponentReference{Schema: local.Config.SchemaVersion, Revision: local.Hash},
	}}
	if firewall.Config.Routed != nil {
		doc.Domains.Network = &v2ComponentReference{Schema: 1, Revision: firewall.Config.Routed.Network.Hash}
	}
	bundle := RoutedActivationBundleV1{Version: 1, Firewall: firewall, LocalServices: local}
	resolved, err := resolveRoutedCompositeV1(doc, bundle.readComponent)
	if err != nil {
		return RoutedActivationBundleV1{}, err
	}
	bundle.Composite = resolved
	return CanonicalRoutedActivationBundleV1(bundle)
}

func (bundle RoutedActivationBundleV1) readComponent(hash string, value any) error {
	out, ok := value.(*Revision)
	if !ok {
		return ErrInvalid
	}
	switch hash {
	case bundle.Firewall.Hash:
		*out = bundle.Firewall
	case bundle.LocalServices.Hash:
		*out = bundle.LocalServices
	default:
		return ErrInvalid
	}
	return nil
}

func CanonicalRoutedActivationBundleV1(bundle RoutedActivationBundleV1) (RoutedActivationBundleV1, error) {
	if bundle.Version != 1 {
		return RoutedActivationBundleV1{}, ErrInvalid
	}
	resolved, err := resolveRoutedCompositeV1(bundle.Composite.Config, bundle.readComponent)
	if err != nil || resolved.Hash != bundle.Composite.Hash {
		return RoutedActivationBundleV1{}, ErrInvalid
	}
	data, err := json.Marshal(bundle)
	if err != nil || len(data) > v2ObjectLimit {
		return RoutedActivationBundleV1{}, ErrInvalid
	}
	var detached RoutedActivationBundleV1
	if json.Unmarshal(data, &detached) != nil {
		return RoutedActivationBundleV1{}, ErrInvalid
	}
	return detached, nil
}

// RoutedTransitionV1 contains only references to typed, context-checked store
// objects. Shape validation alone cannot prove their ownership or reachability.
type RoutedTransitionV1 struct {
	Version      int    `json:"version"`
	Operation    string `json:"operation_id"`
	Previous     string `json:"previous_snapshot"`
	Target       string `json:"target_snapshot"`
	BeforeOwned  string `json:"before_owned_object"`
	TargetOwned  string `json:"target_owned_object"`
	Dependencies string `json:"dependency_object"`
}

func (transition RoutedTransitionV1) ValidShape() bool {
	return transition.Version == 1 && identifier.MatchString(transition.Operation) &&
		validHash(transition.Previous) && validHash(transition.Target) &&
		validHash(transition.BeforeOwned) && validHash(transition.TargetOwned) &&
		validHash(transition.Dependencies)
}
