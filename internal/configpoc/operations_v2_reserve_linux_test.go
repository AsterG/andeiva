//go:build linux

package configpoc

import (
	"errors"
	"testing"
	"time"
)

func TestV2AcceptedFinalizationUsesOnlyReleasedReservations(t *testing.T) {
	for _, action := range []string{"close", "expire"} {
		for _, budget := range []string{"bytes", "inodes"} {
			t.Run(action+"/"+budget, func(t *testing.T) {
				s, area, now, subject := v2Fixture(t, 64)
				target, err := s.namespace(subject, "firewall", now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				other, err := s.namespace(subject, "local_services", now, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				var accepted []v2Operation
				for range 8 {
					op, err := s.admit(subject, target.ID, 1, v2Request{Kind: OpValidate}, now)
					if err != nil {
						t.Fatal(err)
					}
					accepted = append(accepted, op)
				}
				pending, err := s.admit(subject, other.ID, 1, v2Request{Kind: OpValidate}, now)
				if err != nil {
					t.Fatal(err)
				}
				pending, err = s.begin(subject, pending.ID, now)
				if err != nil {
					t.Fatal(err)
				}
				limits := s.budget
				if budget == "bytes" {
					limits.Bytes = s.used.Bytes + s.state.ReservedBytes
				} else {
					limits.Inodes = s.used.Inodes + s.state.ReservedInodes
				}
				s.budget = limits
				switch action {
				case "close":
					err = s.closeNamespace(subject, target.ID, now)
				case "expire":
					err = s.expire(now.Add(901 * time.Second))
				}
				if err != nil {
					t.Fatalf("reserved finalization rejected: %v", err)
				}
				if s.state.ReservedBytes != v2OperationReserveBytes || s.state.ReservedInodes != v2OperationReserveInodes {
					t.Fatal("unrelated pending reservation changed")
				}
				if s.allowance != (v2Budget{}) {
					t.Fatal("allowance escaped finalization")
				}
				current, err := s.lookup(subject, pending.ID)
				if err != nil || current.State != "pending" || !current.Pinned {
					t.Fatal("unrelated pending state changed", err)
				}
				for _, op := range accepted {
					current, err := s.lookup(subject, op.ID)
					if err != nil || current.State != "final" || current.Outcome == nil || current.Pinned {
						t.Fatal("finalization missing", err)
					}
				}
				if s.used.Bytes+s.state.ReservedBytes > limits.Bytes || s.used.Inodes+s.state.ReservedInodes > limits.Inodes {
					t.Fatal("finalization consumed another reserve")
				}
				if err = s.close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := openV2(area, limits)
				if err != nil {
					t.Fatal("durable close/expiry", err)
				}
				defer reopened.close()
				if reopened.state.ReservedBytes != v2OperationReserveBytes {
					t.Fatal("lost pending reserve on reopen")
				}
				if _, err = reopened.begin(subject, accepted[0].ID, now.Add(901*time.Second)); err != nil {
					t.Fatal("terminal retry", err)
				}
			})
		}
	}
}

func TestV2FinalizationFaultRestoresAllowanceAndRetainsReservations(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if _, err = s.admit(subject, ns.ID, 1, v2Request{Kind: OpValidate}, now); err != nil {
			t.Fatal(err)
		}
	}
	previous := s.selector.Current
	reserved := s.state.ReservedBytes
	s.budget.Bytes = s.used.Bytes + reserved
	s.hook = func(at string) error {
		if at == "object_written" {
			return errors.New("injected finalization write failure")
		}
		return nil
	}
	if err = s.closeNamespace(subject, ns.ID, now); err == nil {
		t.Fatal("failed finalization reported success")
	}
	if !s.blocked || s.allowance != (v2Budget{}) || s.selector.Current != previous || s.state.ReservedBytes != reserved {
		t.Fatal("fault lost fence/reservation or leaked allowance")
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if reopened.state.ReservedBytes != reserved || reopened.state.Namespaces[0].Closed {
		t.Fatal("partial closure published")
	}
}

func TestV2PinReleaseUsesOwnReservationAtBudget(t *testing.T) {
	for _, kind := range []string{"bytes", "inodes"} {
		t.Run(kind, func(t *testing.T) {
			s, area, now, subject := v2Fixture(t, 64)
			ns, err := s.namespace(subject, "firewall", now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			seconds := uint64(30)
			origin, err := s.admit(subject, ns.ID, 1, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.begin(subject, origin.ID, now); err != nil {
				t.Fatal(err)
			}
			if _, err = s.finish(subject, origin.ID, v2Outcome{Code: "applied_pending_confirmation", Generation: 1}, []byte("catalogue fixture"), now, true); err != nil {
				t.Fatal(err)
			}
			confirmation, err := s.admit(subject, ns.ID, 1, v2Request{Kind: OpConfirm, Origin: origin.ID, Target: checkpointDigest([]byte("revision"))}, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.begin(subject, confirmation.ID, now); err != nil {
				t.Fatal(err)
			}
			if _, err = s.finish(subject, confirmation.ID, v2Outcome{Code: "applied", Generation: 1}, []byte("verified fixture confirmation"), now, false); err != nil {
				t.Fatal(err)
			}
			for range 4 {
				if _, err = s.admit(subject, ns.ID, 1, v2Request{Kind: OpValidate}, now); err != nil {
					t.Fatal(err)
				}
			}
			before := s.state.ReservedBytes
			limits := s.budget
			if kind == "bytes" {
				limits.Bytes = s.used.Bytes + s.state.ReservedBytes
			} else {
				limits.Inodes = s.used.Inodes + s.state.ReservedInodes
			}
			s.budget = limits
			if err = s.releasePin(subject, origin.ID, confirmation.ID, now); err != nil {
				t.Fatal("own release budget unavailable", err)
			}
			if s.state.ReservedBytes != before-v2OperationReserveBytes || s.allowance != (v2Budget{}) {
				t.Fatal("another operation reserve was consumed")
			}
			if err = s.close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openV2(area, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.close()
			op, err := reopened.lookup(subject, origin.ID)
			if err != nil || op.Pinned {
				t.Fatal("pin release not durable", err)
			}
		})
	}
}
