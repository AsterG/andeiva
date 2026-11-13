//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type scopeNotifierDoubleV3 struct {
	calls      []string
	fds        []int
	fail       int
	barrierErr error
}

func (n *scopeNotifierDoubleV3) send(_ context.Context, s string, fd int) error {
	n.calls = append(n.calls, s)
	n.fds = append(n.fds, fd)
	if len(n.calls) == n.fail {
		return ErrUnavailable
	}
	return nil
}
func (n *scopeNotifierDoubleV3) barrier(context.Context) error {
	n.calls = append(n.calls, "BARRIER=1")
	return n.barrierErr
}
func scopeStoreJSONV3(t *testing.T, facts map[string]scopeRecoveryStoredV3) []byte {
	t.Helper()
	entries := [][]any{}
	for _, name := range scopeRecoveryNamesV3 {
		if f, ok := facts[name]; ok {
			entries = append(entries, []any{name, f.Mode, f.Major, f.Minor, f.Inode, f.Rmajor, f.Rminor, "ignored", f.Flags})
		}
	}
	raw, err := json.Marshal(struct {
		Type string `json:"type"`
		Data any    `json:"data"`
	}{"a(suuutuusu)", []any{entries}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRoutedScopeRecoveryV3Exchange(t *testing.T) {
	facts := map[string]scopeRecoveryStoredV3{}
	fds := []int{}
	for i, name := range scopeRecoveryNamesV3 {
		facts[name] = scopeRecoveryStoredV3{Mode: 0100600, Inode: uint64(i + 100)}
		fds = append(fds, i+30)
	}
	full, empty := scopeStoreJSONV3(t, facts), scopeStoreJSONV3(t, nil)
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint(remove), func(t *testing.T) {
			before, after := empty, full
			if remove {
				before, after = full, empty
			}
			for _, failure := range []string{"", "before", "send", "barrier", "after", "read_error", "cancel"} {
				t.Run(failure, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					n := &scopeNotifierDoubleV3{}
					reads := 0
					if failure == "send" {
						n.fail = 3
					}
					if failure == "barrier" {
						n.barrierErr = ErrUnavailable
					}
					read := func(context.Context) ([]byte, error) {
						reads++
						if reads == 1 {
							if failure == "before" {
								return []byte(`{}`), nil
							}
							return before, nil
						}
						if len(n.calls) != 8 || n.calls[7] != "BARRIER=1" {
							t.Fatal("readback before all notifications/barrier")
						}
						if failure == "after" {
							return before, nil
						}
						if failure == "read_error" {
							return nil, ErrUnavailable
						}
						if failure == "cancel" {
							cancel()
						}
						return after, nil
					}
					err := exchangeScopeRecoveryStoreV3(ctx, n, read, facts, fds, remove)
					if (err == nil) != (failure == "") {
						t.Fatalf("failure %s result %v", failure, err)
					}
					if failure == "before" && len(n.calls) != 0 {
						t.Fatal("mutated unknown manager state")
					}
					if failure == "send" && (len(n.calls) != 3 || reads != 1) {
						t.Fatal("partial store was retried or discarded")
					}
					if failure == "barrier" && reads != 1 {
						t.Fatal("continued after uncertain barrier")
					}
					for i, s := range n.calls {
						if s == "BARRIER=1" {
							continue
						}
						want := "FDSTORE=1\nFDPOLL=0\nFDNAME=" + scopeRecoveryNamesV3[i]
						fd := fds[i]
						if remove {
							want = "FDSTOREREMOVE=1\nFDNAME=" + scopeRecoveryNamesV3[i]
							fd = -1
						}
						if s != want || n.fds[i] != fd {
							t.Fatal("unbounded or wrong notification")
						}
					}
				})
			}
		})
	}
	for _, bad := range []string{`{"type":"a(suuutuusu)","data":[null]}`, `{"type":"a(suuutuusu)","data":[]}`} {
		if scopeRecoveryStoreMatchesV3([]byte(bad), nil) {
			t.Fatal("malformed empty store accepted")
		}
	}
}
func TestRoutedScopeRecoveryV3InheritedNames(t *testing.T) {
	names := append([]string{RoutedScopeManagementFDNameV3}, scopeRecoveryNamesV3[:]...)
	for i := 0; i < len(names); i++ {
		rotated := append(append([]string{}, names[i:]...), names[:i]...)
		got, err := scopeRecoveryInheritedNamesV3("200", "8", strings.Join(rotated, ":"), 200)
		if err != nil {
			t.Fatal(err)
		}
		for i, n := range rotated {
			if got[n] != i+3 {
				t.Fatal("assumed descriptor order")
			}
		}
	}
	got, err := scopeRecoveryInheritedNamesV3("200", "1", RoutedScopeManagementFDNameV3, 200)
	if err != nil || !reflect.DeepEqual(got, map[string]int{RoutedScopeManagementFDNameV3: 3}) {
		t.Fatal("management-only refused")
	}
	for _, tc := range []struct{ pid, count, names string }{
		{"201", "8", strings.Join(names, ":")}, {"200", "08", strings.Join(names, ":")}, {"200", "9", strings.Join(append(names, "extra"), ":")},
		{"200", "7", strings.Join(names[1:], ":")}, {"200", "2", strings.Join(names[:2], ":")}, {"200", "1", "unknown"}, {"200", "2", RoutedScopeManagementFDNameV3 + ":" + RoutedScopeManagementFDNameV3},
	} {
		if _, err := scopeRecoveryInheritedNamesV3(tc.pid, tc.count, tc.names, 200); err == nil {
			t.Fatal("invalid inheritance accepted", tc)
		}
	}
}
func TestRoutedScopeRecoveryV3BarrierUsesTransferredPipe(t *testing.T) {
	for _, mode := range []string{"close", "data", "retain"} {
		t.Run(mode, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			defer unix.Close(pair[1])
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if err := scopeNotifyWaitV3(ctx, pair[1], unix.POLLIN); err != nil {
					done <- err
					return
				}
				data, oob := make([]byte, 64), make([]byte, unix.CmsgSpace(4))
				n, on, flags, _, err := unix.Recvmsg(pair[1], data, oob, 0)
				if err != nil || flags != 0 || string(data[:n]) != "BARRIER=1" {
					done <- ErrIdentity
					return
				}
				messages, err := unix.ParseSocketControlMessage(oob[:on])
				if err != nil || len(messages) != 1 {
					done <- ErrIdentity
					return
				}
				rights, err := unix.ParseUnixRights(&messages[0])
				if err != nil || len(rights) != 1 {
					done <- ErrIdentity
					return
				}
				defer unix.Close(rights[0])
				switch mode {
				case "data":
					_, err = unix.Write(rights[0], []byte{1})
				case "retain":
					<-ctx.Done()
				}
				done <- err
			}()
			err = (&scopeRecoveryNotifyV3{fd: pair[0]}).barrier(ctx)
			if mode == "close" && err != nil {
				t.Fatal(err)
			}
			if mode == "data" && !errors.Is(err, ErrIdentity) {
				t.Fatalf("pipe data accepted: %v", err)
			}
			if mode == "retain" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unacknowledged barrier accepted: %v", err)
			}
			if peerErr := <-done; peerErr != nil {
				t.Fatal(peerErr)
			}
		})
	}
}
func TestRoutedScopeRecoveryV3RejectsNonCanonicalCount(t *testing.T) {
	for _, n := range []int{-1, 0, 9, 100000} {
		if _, err := scopeRecoveryInheritedNamesV3("200", strconv.Itoa(n), RoutedScopeManagementFDNameV3, 200); err == nil {
			t.Fatal(n)
		}
	}
}
