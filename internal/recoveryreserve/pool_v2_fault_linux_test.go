//go:build linux

package recoveryreserve

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func TestPoolV2ClaimAndWriteFaultBoundaries(t *testing.T) {
	for _, point := range []string{"claim_first_written", "claim_first_synced", "claim_second_written", "claim_second_synced", "write_payload_written", "write_payload_synced", "write_header_written", "write_header_synced"} {
		t.Run(point, func(t *testing.T) {
			p, area := preparedV2(t, 1)
			var claim SlotClaimV2
			var err error
			if point[:5] != "claim" {
				claim, err = p.Claim("owner")
				if err != nil {
					t.Fatal(err)
				}
			}
			p.hook = func(name string) error {
				if name == point {
					return errors.New("interrupted")
				}
				return nil
			}
			if point[:5] == "claim" {
				_, err = p.Claim("owner")
			} else {
				_, err = p.WriteOnce(claim, []byte("selected plan"), scopeForV2("owner"))
			}
			if err == nil || !p.blocked {
				t.Fatal("boundary did not fence", err)
			}
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			before := snapshotV2(t, area)
			p, err = OpenV2(area)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			observed, err := p.inspect(0)
			if err != nil {
				t.Fatal(err)
			}
			if observed.record.State == "ready" {
				t.Fatal("interrupted claim became free")
			}
			if _, err = p.Claim("foreign"); err == nil {
				t.Fatal("interrupted owner stolen")
			}
			if !reflect.DeepEqual(before, snapshotV2(t, area)) {
				t.Fatal("refusal changed bytes")
			}
		})
	}
}

func TestPoolV2RetirementEveryBankBoundary(t *testing.T) {
	for _, phase := range []string{"retired_held", "free_prepared", "ready"} {
		for _, boundary := range []string{"first_written", "first_synced", "second_written", "second_synced"} {
			point := "retire_" + phase + "_" + boundary
			t.Run(point, func(t *testing.T) {
				p, area := preparedV2(t, 1)
				claim, err := p.Claim("owner")
				if err != nil {
					t.Fatal(err)
				}
				scope := scopeForV2("owner")
				binding, err := p.WriteOnce(claim, []byte("protected archive source"), scope)
				if err != nil {
					t.Fatal(err)
				}
				expected := ExpectedV2{claim, &binding}
				proof := proofForV2(scope)
				p.hook = func(name string) error {
					if name == point {
						return errors.New("interrupted")
					}
					return nil
				}
				if err = p.RetireCAS(expected, proof); err == nil || !p.blocked {
					t.Fatal("retire missed boundary", err)
				}
				if err = p.Close(); err != nil {
					t.Fatal(err)
				}
				p, err = OpenV2(area)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				observed, err := p.inspect(0)
				if err != nil {
					t.Fatal(err)
				}
				if observed.record.State != "ready" || !observed.identical {
					before := snapshotV2(t, area)
					if _, err = p.Claim("foreign"); err == nil || !reflect.DeepEqual(before, snapshotV2(t, area)) {
						t.Fatal("mixed bank pair became allocatable", err)
					}
				}
				if err = p.RetireCAS(expected, proof); err != nil {
					t.Fatal("exact retirement could not resume", err)
				}
				next, err := p.Claim("next-owner")
				if err != nil || next.Epoch != claim.Epoch+1 {
					t.Fatal("next epoch", err)
				}
				before := snapshotV2(t, area)
				if err = p.RetireCAS(expected, proof); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
					t.Fatal("old proof changed next epoch", err)
				}
			})
		}
	}
}

func TestPoolV2UnknownOrTornBankNeverFallsBackOrFrees(t *testing.T) {
	for _, mode := range []string{"written-header", "written-payload", "first-claim", "retire-ready", "duplicate-fields", "wrong-slot", "same-sequence-conflict"} {
		t.Run(mode, func(t *testing.T) {
			p, area := preparedV2(t, 1)
			claim, err := p.Claim("owner")
			if err != nil {
				t.Fatal(err)
			}
			scope := scopeForV2("owner")
			binding, err := p.WriteOnce(claim, []byte("exact selected record"), scope)
			if err != nil {
				t.Fatal(err)
			}
			bank := int(binding.Sequence % 2)
			offset := int64(bank) * bankSizeV2(p.manifest.Capacity)
			switch mode {
			case "written-header":
				_, err = p.slots[0].file.WriteAt([]byte("broken"), offset)
			case "written-payload":
				_, err = p.slots[0].file.WriteAt([]byte("X"), offset+headerV2)
			case "first-claim":
				_, err = p.slots[0].file.WriteAt([]byte("broken"), int64(1-bank)*bankSizeV2(p.manifest.Capacity))
			case "retire-ready":
				err = p.RetireCAS(ExpectedV2{claim, &binding}, proofForV2(scope))
				if err != nil {
					t.Fatal(err)
				}
				_, err = p.slots[0].file.WriteAt([]byte("broken"), 0)
			case "duplicate-fields":
				_, err = p.slots[0].file.WriteAt([]byte(`{"record":{},"record":{},"checksum":"duplicate"}`), offset)
			case "wrong-slot":
				r, _, e := p.readBank(0, bank)
				if e != nil {
					t.Fatal(e)
				}
				r.Slot = 1
				err = writeHeaderV2(p.slots[0].file, offset, r)
			case "same-sequence-conflict":
				r, _, e := p.readBank(0, bank)
				if e != nil {
					t.Fatal(e)
				}
				r.ScopeHash = digest([]byte("other scope"))
				other := int64(1-bank) * bankSizeV2(p.manifest.Capacity)
				if _, e = p.slots[0].file.WriteAt([]byte("exact selected record"), other+headerV2); e != nil {
					t.Fatal(e)
				}
				err = writeHeaderV2(p.slots[0].file, other, r)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = p.slots[0].file.Sync(); err != nil {
				t.Fatal(err)
			}
			before := snapshotV2(t, area)
			if _, err = p.ReadBound(binding); err == nil {
				t.Fatal("unknown bank accepted selected result")
			}
			if _, err = p.InspectClaimed(claim); err == nil {
				t.Fatal("unknown bank accepted candidate")
			}
			if _, err = p.Claim("foreign"); err == nil {
				t.Fatal("unknown bank allocated")
			}
			if !reflect.DeepEqual(before, snapshotV2(t, area)) {
				t.Fatal("unknown bank repaired automatically")
			}
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, e := OpenV2(area); e == nil {
				_ = reopened.Close()
				t.Fatal("corrupt layout accepted")
			}
			if !reflect.DeepEqual(before, snapshotV2(t, area)) {
				t.Fatal("open repaired foreign bytes")
			}
		})
	}
}

var reserveChildV2 = flag.String("reserve-v2-child", "", "private pool v2 process boundary")
var reserveAreaV2 = flag.String("reserve-v2-area", "", "private pool v2 fixture")

func TestPoolV2ProcessExit(t *testing.T) {
	if *reserveChildV2 != "" {
		area, err := os.OpenRoot(*reserveAreaV2)
		if err != nil {
			t.Fatal(err)
		}
		defer area.Close()
		p, err := OpenV2(area)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		point := *reserveChildV2
		if point == "claim_first_synced" {
			p.hook = func(name string) error {
				if name == point {
					os.Exit(23)
				}
				return nil
			}
			_, _ = p.Claim("owner")
			t.Fatal("missed claim")
		}
		claim, err := p.Claim("owner")
		if err != nil {
			t.Fatal(err)
		}
		scope := scopeForV2("owner")
		payload := []byte("process recovery capsule")
		if point == "write_payload_synced" || point == "write_header_synced" {
			p.hook = func(name string) error {
				if name == point {
					os.Exit(23)
				}
				return nil
			}
			_, _ = p.WriteOnce(claim, payload, scope)
			t.Fatal("missed write")
		}
		binding, err := p.WriteOnce(claim, payload, scope)
		if err != nil {
			t.Fatal(err)
		}
		if point != "retire_retired_held_first_synced" && point != "retire_free_prepared_first_synced" && point != "retire_ready_first_synced" {
			t.Fatal("invalid child boundary")
		}
		p.hook = func(name string) error {
			if name == point {
				os.Exit(23)
			}
			return nil
		}
		_ = p.RetireCAS(ExpectedV2{claim, &binding}, proofForV2(scope))
		t.Fatal("missed retirement")
	}
	for _, point := range []string{"claim_first_synced", "write_payload_synced", "write_header_synced", "retire_retired_held_first_synced", "retire_free_prepared_first_synced", "retire_ready_first_synced"} {
		t.Run(point, func(t *testing.T) {
			p, area := preparedV2(t, 1)
			var claim SlotClaimV2
			var binding BindingV2
			scope := scopeForV2("owner")
			payload := []byte("process recovery capsule")
			var err error
			if point != "claim_first_synced" {
				claim, err = p.Claim("owner")
				if err != nil {
					t.Fatal(err)
				}
			}
			if point[:6] == "retire" {
				binding, err = p.WriteOnce(claim, payload, scope)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "-test.run=^TestPoolV2ProcessExit$", "-reserve-v2-child="+point, "-reserve-v2-area="+area.Name())
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("child: %v %s", err, output)
			}
			p, err = OpenV2(area)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if point == "claim_first_synced" {
				before := snapshotV2(t, area)
				if _, err = p.Claim("foreign"); err == nil || !reflect.DeepEqual(before, snapshotV2(t, area)) {
					t.Fatal("partial claim released", err)
				}
				return
			}
			if point[:6] == "retire" {
				if err = p.RetireCAS(ExpectedV2{claim, &binding}, proofForV2(scope)); err != nil {
					t.Fatal("retirement resume", err)
				}
				if _, err = p.Claim("next"); err != nil {
					t.Fatal(err)
				}
				return
			}
			if point == "write_payload_synced" {
				if _, err = p.InspectClaimed(claim); err == nil {
					t.Fatal("uncommitted payload became candidate")
				}
			}
			binding, err = p.WriteOnce(claim, payload, scope)
			if err != nil {
				t.Fatal("same immutable write recovery", err)
			}
			data, err := p.ReadBound(binding)
			if err != nil || !bytes.Equal(data, payload) {
				t.Fatal("recovered binding", err)
			}
		})
	}
}
