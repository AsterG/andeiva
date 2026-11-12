package localadmin

import (
	"context"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
)

// PendingReceiversV2 reads an in-memory listener-factory registry. It must not
// call auth, coordinator, engines, filesystem or network while store.mu is held.
type PendingReceiversV2 func(configpoc.Revision) ([]ProofReceiverV2, error)
type PreparedPolicyV2 struct {
	book      *PreparedProofBookV2
	receivers PendingReceiversV2
}
type localHandleV2 struct {
	policy   *PreparedPolicyV2
	identity ProofIdentityV2
	receiver ProofReceiverV2
	evidence ProofEvidenceV2
}

func (*localHandleV2) LocalProofHandleV2() {}
func (*localHandleV2) String() string      { return "<local proof handle>" }
func (*localHandleV2) GoString() string    { return "<local proof handle>" }

func NewPreparedPolicyV2(book *PreparedProofBookV2, receivers PendingReceiversV2) (*PreparedPolicyV2, error) {
	if book == nil || !book.ready() || receivers == nil {
		return nil, configpoc.ErrInvalid
	}
	return &PreparedPolicyV2{book: book, receivers: receivers}, nil
}
func (p *PreparedPolicyV2) AuthenticationAuthority() *adminauth.Manager {
	if p == nil || p.book == nil {
		return nil
	}
	return p.book.auth
}
func receiverV2(r configpoc.LocalReceiverV2) ProofReceiverV2 {
	return ProofReceiverV2{Run: r.Run, Instance: r.Instance, Endpoint: r.Endpoint, ActivationHash: r.ActivationHash, Namespace: r.Namespace, Surface: r.Surface}
}
func (p *PreparedPolicyV2) Authenticate(binding adminauth.SessionBinding, receiver configpoc.LocalReceiverV2, evidence configpoc.LocalEvidenceV2) (configpoc.LocalHandleV2, error) {
	if p == nil || p.book == nil {
		return nil, configpoc.ErrDenied
	}
	identity, err := p.book.Authenticate(binding)
	if err != nil {
		return nil, err
	}
	if !proofSurfaceV2(receiver.Surface) || !validHex(receiver.Run, 16) || !validHex(receiver.Instance, 16) || receiver.Namespace == 0 || (!identifier.MatchString(receiver.Endpoint) && !validBindingID(receiver.Endpoint)) || (receiver.ActivationHash != "" && !validHex(receiver.ActivationHash, 32)) || len(evidence.Endpoints) > 8 {
		return nil, configpoc.ErrDenied
	}
	if evidence.Recovery != "" && len(evidence.Recovery) != 64 {
		return nil, configpoc.ErrDenied
	}
	for _, token := range evidence.Endpoints {
		if len(token) != 64 {
			return nil, configpoc.ErrDenied
		}
	}
	return &localHandleV2{policy: p, identity: identity, receiver: receiverV2(receiver), evidence: ProofEvidenceV2{Recovery: evidence.Recovery, Endpoints: append([]string{}, evidence.Endpoints...)}}, nil
}
func (p *PreparedPolicyV2) Validate(scope configpoc.LocalProofScopeV2) error {
	if p == nil || p.book == nil || !p.book.ready() || !p.book.validate(scope) {
		return configpoc.ErrInvalid
	}
	return nil
}
func (p *PreparedPolicyV2) handle(raw configpoc.LocalHandleV2, scope configpoc.LocalProofScopeV2) (*localHandleV2, error) {
	h, ok := raw.(*localHandleV2)
	if !ok || h == nil || h.policy != p || !p.book.validIdentity(h.identity, scope.Binding()) {
		return nil, configpoc.ErrDenied
	}
	return h, nil
}
func (p *PreparedPolicyV2) Issue(raw configpoc.LocalHandleV2, scope configpoc.LocalProofScopeV2) (configpoc.LocalTokenV2, error) {
	h, err := p.handle(raw, scope)
	if err != nil {
		return configpoc.LocalTokenV2{}, err
	}
	proof, err := p.book.Issue(h.identity, scope, h.receiver)
	if err != nil {
		return configpoc.LocalTokenV2{}, err
	}
	return configpoc.LocalTokenV2{Token: proof.Token, ExpiresAt: proof.ExpiresAt}, nil
}

type emptyLocalReservationV2 struct{}

func (emptyLocalReservationV2) Finish(bool) {}
func (p *PreparedPolicyV2) Reserve(raw configpoc.LocalHandleV2, scope configpoc.LocalProofScopeV2) (configpoc.LocalReservationV2, error) {
	h, err := p.handle(raw, scope)
	if err != nil {
		return nil, err
	}
	if scope.Binding().Kind == configpoc.OpStage || scope.Binding().Kind == configpoc.OpValidate {
		if h.evidence.Recovery != "" || len(h.evidence.Endpoints) != 0 {
			return nil, configpoc.ErrDenied
		}
		return emptyLocalReservationV2{}, nil
	}
	return p.book.Reserve(h.identity, scope, h.evidence)
}
func (p *PreparedPolicyV2) PublishPending(view configpoc.LocalPendingViewV2) error {
	if p == nil || p.book == nil || p.receivers == nil {
		return configpoc.ErrRecovery
	}
	receivers, err := p.receivers(view.Local)
	if err != nil {
		return err
	}
	return p.book.publishPendingV2(view, receivers)
}
func (p *PreparedPolicyV2) Invalidate() {
	if p != nil && p.book != nil {
		p.book.Invalidate()
	}
}

func (b *PreparedProofBookV2) publishPendingV2(view configpoc.LocalPendingViewV2, receivers []ProofReceiverV2) error {
	if !b.ready() {
		return configpoc.ErrRecovery
	}
	if !view.Valid() || validateProfile(view.Local.Config, b.inventory) != nil {
		return configpoc.ErrInvalid
	}
	binding := configpoc.LocalProofBindingV2{Lineage: view.Lineage, Subject: view.Subject, Login: view.Login, CredentialRevision: view.CredentialRevision, Kind: configpoc.OpConfirm, Purpose: "confirm", Generation: view.Generation, LocalGeneration: view.LocalGeneration, Current: view.Target, Target: view.Target, LocalTarget: view.Local.Hash, Origin: view.Origin, Lease: view.Lease, Deadline: view.Deadline, ExecuteBefore: view.Deadline}
	return b.publishV2(binding, view.Local, receivers)
}

// PreparedBridgeV2 is bound by a real listener factory. Receiver identity is not
// a request field; transports pass only admitted IDs, purpose and opaque tokens.
type PreparedBridgeV2 struct {
	service  *configpoc.ServiceV2
	receiver configpoc.LocalReceiverV2
}

func NewPreparedBridgeV2(service *configpoc.ServiceV2, receiver ProofReceiverV2) (*PreparedBridgeV2, error) {
	if service == nil || !validHex(receiver.Run, 16) || !validHex(receiver.Instance, 16) || receiver.Namespace == 0 || !proofSurfaceV2(receiver.Surface) || (!identifier.MatchString(receiver.Endpoint) && !validBindingID(receiver.Endpoint)) || (receiver.ActivationHash != "" && !validHex(receiver.ActivationHash, 32)) {
		return nil, configpoc.ErrInvalid
	}
	return &PreparedBridgeV2{service: service, receiver: configpoc.LocalReceiverV2{Run: receiver.Run, Instance: receiver.Instance, Endpoint: receiver.Endpoint, ActivationHash: receiver.ActivationHash, Namespace: receiver.Namespace, Surface: receiver.Surface}}, nil
}
func (b *PreparedBridgeV2) Issue(binding adminauth.SessionBinding, id, purpose string) (configpoc.LocalTokenV2, error) {
	if b == nil || b.service == nil {
		return configpoc.LocalTokenV2{}, configpoc.ErrDenied
	}
	return b.service.IssueLocalProofV2(binding, id, purpose, b.receiver)
}
func (b *PreparedBridgeV2) Execute(ctx context.Context, binding adminauth.SessionBinding, id string, evidence ProofEvidenceV2) (configpoc.ObservationV2, error) {
	if b == nil || b.service == nil {
		return configpoc.ObservationV2{}, configpoc.ErrDenied
	}
	return b.service.ExecuteLocalV2(ctx, binding, id, b.receiver, configpoc.LocalEvidenceV2{Recovery: evidence.Recovery, Endpoints: append([]string{}, evidence.Endpoints...)})
}
