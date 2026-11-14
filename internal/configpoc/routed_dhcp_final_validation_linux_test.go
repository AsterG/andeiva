//go:build linux

package configpoc

import (
	"context"
	"os"
	"reflect"
	"testing"
)

// Repeat the private dependent reads, without issuing an authority object.
func dhcpCandidateDependenciesV3(t *testing.T, v *selectedViewV2) {
	t.Helper()
	if err := validateRoutedDHCPSelectedV3(v.store.state, v.store.readObject); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRoutedDHCPWorkV3(v.store.state.RoutedDHCP.Work, v.store.state.Lineage, v.store.readObject); err != nil {
		t.Fatal(err)
	}
}

func TestDHCPFinalValidationV3SinglePassBudget(t *testing.T) {
	for _, policy := range []SelectionReaderPolicyV2{SelectionFullHistoryV2, SelectionActionAuthorityV2} {
		t.Run(string(policy), func(t *testing.T) {
			r, _, _, w, _ := selectedDHCPReaderFixtureV3(t)
			r.options.Policy = policy
			ctx := context.Background()
			hash, err := w.Prepare(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var beforeClose uint64
			measure := func(duplicate bool) (uint64, error) {
				var v *selectedViewV2
				var err error
				if duplicate {
					v, err = r.read(ctx)
				} else {
					v, err = r.readCandidateWithGateV2(ctx, nil)
				}
				if err != nil {
					return 0, err
				}
				dhcpCandidateDependenciesV3(t, v)
				err = r.revalidate(ctx, v)
				if !duplicate {
					beforeClose = v.graph.report.IOCalls
				}
				closeErr := v.graph.closeSelectedV2()
				if err == nil {
					err = closeErr
				}
				return v.graph.report.IOCalls, err
			}
			single, err := measure(false)
			if err != nil {
				t.Fatal(err)
			}
			double, err := measure(true)
			if err != nil || double <= single {
				t.Fatalf("missing validation saving: single=%d double=%d err=%v", single, double, err)
			}
			t.Logf("charged IOCalls single=%d duplicate=%d saved=%d", single, double, double-single)
			r.options.Budget.IOCalls = single
			selected, err := r.ResolveDHCPCurrentV3(ctx, hash)
			if err != nil || selected.Epoch() != 1 || selected.Reference().WorkHash != hash {
				t.Fatal("public resolver exceeded single-pass budget", err)
			}
			if _, err = measure(true); err == nil {
				t.Fatal("duplicate final validation fit single-pass budget")
			}
			// Final validation can succeed while counted FD cleanup exhausts
			// the budget. The public deferred close must erase that proof.
			if single <= beforeClose {
				t.Fatal("fixture has no charged cleanup")
			}
			r.options.Budget.IOCalls = single - 1
			selected, err = r.ResolveDHCPCurrentV3(ctx, hash)
			if err == nil || !reflect.DeepEqual(selected, RoutedDHCPSelectedV3{}) {
				t.Fatal("cleanup budget failure published authority", err)
			}
		})
	}
}

func TestDHCPFinalValidationV3RejectsCandidateMutation(t *testing.T) {
	for _, policy := range []SelectionReaderPolicyV2{SelectionFullHistoryV2, SelectionActionAuthorityV2} {
		t.Run(string(policy), func(t *testing.T) {
			r, c, _, w, _ := selectedDHCPReaderFixtureV3(t)
			r.options.Policy = policy
			hash, err := w.Prepare(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			kinds := []string{"selector", "pending", "work", "dependency", "pool", "cancel"}
			// Action policy retains even uncached dependencies read later. Full
			// history relies on its complete graph and pinned-cache validation;
			// do not claim it tracks arbitrary additions outside that graph.
			if policy == SelectionActionAuthorityV2 {
				kinds = append(kinds, "late-dependency")
			}
			for _, kind := range kinds {
				t.Run(kind, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					v, err := r.readCandidateWithGateV2(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := v.graph.closeSelectedV2(); err != nil {
							t.Error(err)
						}
						if v.graph.active != 0 || len(v.graph.cache.entries) != 0 {
							t.Error("candidate retained resources")
						}
					}()
					dhcpCandidateDependenciesV3(t, v)
					name := ""
					switch kind {
					case "selector":
						name = "selected.json"
					case "work":
						name, err = v2ObjectName(hash)
					case "dependency":
						work, e := loadRoutedDHCPWorkV3(hash, v.store.state.Lineage, v.store.readObject)
						if e != nil {
							t.Fatal(e)
						}
						name, err = v2ObjectName(work.Configuration)
					case "late-dependency":
						// This dependency was not in the candidate graph. A final
						// validation must also cover reads made after construction.
						value := struct {
							Value string `json:"value"`
						}{"late-read"}
						dep, e := c.store.object(value)
						if e != nil {
							t.Fatal(e)
						}
						var loaded struct {
							Value string `json:"value"`
						}
						if e = v.graph.object(dep, &loaded); e != nil {
							t.Fatal(e)
						}
						name, err = v2ObjectName(dep)
					case "pending":
						if err := r.area.WriteFile("selection.pending", []byte("pending"), 0640); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if err := r.area.Remove("selection.pending"); err != nil {
								t.Error(err)
							}
						}()
					case "pool":
						original := r.options.Plan
						r.options.Plan = r.options.Admission
						defer func() { r.options.Plan = original }()
					case "cancel":
						cancel()
					}
					if err != nil {
						t.Fatal(err)
					}
					if name != "" {
						f, err := r.area.OpenFile(name, os.O_RDWR, 0)
						if err != nil {
							t.Fatal(err)
						}
						defer func() {
							if err := f.Close(); err != nil {
								t.Error(err)
							}
						}()
						var first [1]byte
						if _, err := f.ReadAt(first[:], 0); err != nil {
							t.Fatal(err)
						}
						if _, err := f.WriteAt([]byte("!"), 0); err != nil {
							t.Fatal(err)
						}
						defer func() {
							if _, err := f.WriteAt(first[:], 0); err != nil {
								t.Error(err)
							}
						}()
					}
					if err := r.revalidate(ctx, v); err == nil {
						t.Fatal("changed candidate validated")
					}
					// A late-only dependency belongs solely to this private read;
					// all other cases must also refuse a fresh public resolution.
					if kind != "late-dependency" {
						proof, err := r.ResolveDHCPCurrentV3(ctx, hash)
						if err == nil || !reflect.DeepEqual(proof, RoutedDHCPSelectedV3{}) {
							t.Fatal("failed read issued authority", err)
						}
					}
				})
			}
		})
	}
}
