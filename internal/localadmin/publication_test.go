package localadmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestEndpointProofRequiresPublishedActivationAndNewListenerInstance(t *testing.T) {
	f := newFixture(t)
	_, first := f.commit()
	before := f.execute(f.confirm(first))
	old := actor()
	old.EndpointID = BindingEndpointID(expectedListeners(before.Running.Config)[0])
	old.ActivationHash = before.Running.Hash
	stage := f.request(configpoc.OpStage)
	c := copyValue(before.Running.Config)
	c.LocalServices.Services[0].Bindings[0].Sources = []string{"198.18.0.3/32"}
	stage.Transaction.Config = &c
	staged := f.execute(stage)
	commit := f.request(configpoc.OpCommit)
	commit.Transaction.ConfirmFor = 30 * time.Second
	commit.RecoveryProof = f.proof(actor(), commit, staged.Candidate.Revision.Hash, commit.Transaction.Key)
	future := ProofRequest{Generation: staged.Generation + 1, Target: staged.Candidate.Revision.Hash, Lease: commit.Transaction.Key}
	if _, err := f.s.IssueProof(old, future); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal("preissued future proof", err)
	}
	newInstance := old
	newInstance.ActivationHash = future.Target
	f.m.onApply = func() {
		if _, err := f.s.IssueProof(newInstance, future); !errors.Is(err, configpoc.ErrDenied) {
			t.Error("proof emitted before pending publication", err)
		}
	}
	pending := f.execute(commit)
	f.m.onApply = nil
	request := ProofRequest{Generation: pending.Generation, Target: pending.Running.Hash, Lease: pending.Pending.Lease}
	if _, err := f.s.IssueProof(old, request); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal("old in-flight connection attested new policy", err)
	}
	if _, err := f.s.IssueProof(newInstance, request); err != nil {
		t.Fatal("new authenticated instance rejected", err)
	}
	confirmed := f.execute(f.confirm(pending))
	if confirmed.Pending != nil || confirmed.Running.Hash != pending.Running.Hash {
		t.Fatal("confirmation failed")
	}
	if _, err := f.s.IssueProof(newInstance, request); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal("proof emitted after pending ended", err)
	}
}

func TestExpiredPendingAndWrongOwnerCannotObtainEndpointProof(t *testing.T) {
	f := newFixture(t)
	_, pending := f.commit()
	c := actor()
	c.EndpointID = BindingEndpointID(expectedListeners(pending.Running.Config)[0])
	c.ActivationHash = pending.Running.Hash
	r := ProofRequest{Generation: pending.Generation, Target: pending.Running.Hash, Lease: pending.Pending.Lease}
	c.Principal.ID = "bob"
	if _, err := f.s.IssueProof(c, r); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal("foreign actor proof", err)
	}
	c.Principal.ID = "alice"
	f.s.proofs.now = func() time.Time { return pending.Pending.Deadline }
	if _, err := f.s.IssueProof(c, r); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal("expired pending proof", err)
	}
	// No helper query is needed to deny these emission requests.
	if _, err := f.s.Status(context.Background(), actor()); err != nil {
		t.Fatal(err)
	}
}

func TestDisconnectDuringOwnedListenerReplacementDoesNotCancelCommit(t *testing.T) {
	f := newFixture(t)
	f.stage(true)
	before := f.snapshot()
	r := f.request(configpoc.OpCommit)
	r.Transaction.ConfirmFor = 30 * time.Second
	r.RecoveryProof = f.proof(actor(), r, before.Candidate.Revision.Hash, r.Transaction.Key)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.m.onApply = cancel
	committed, err := f.s.Execute(ctx, actor(), r)
	if err != nil || committed.Pending == nil || committed.Running.Hash != before.Candidate.Revision.Hash {
		t.Fatal("self-listener disconnect cancelled accepted commit", err)
	}
	f.m.onApply = nil
	counts := f.m.counts()
	if _, err = f.s.Execute(ctx, actor(), r); !errors.Is(err, context.Canceled) || f.m.counts() != counts {
		t.Fatal("pre-cancelled request admitted", err)
	}
}
