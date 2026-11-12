package nftfixture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestListenerControlsRetainCauseAndStopAtFailure(t *testing.T) {
	for _, label := range []string{"ANDEIVA_NFT_FIXTURE_LISTENER", "ANDEIVA_NFT_FIXTURE_REVERSE_LISTENER"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded, os.ErrPermission, errors.New("ANDEIVA_NFT_PROBE_NONCE_MISMATCH")} {
			t.Run(label+"/"+cause.Error(), func(t *testing.T) {
				ctx := context.Background()
				calls := []string{}
				err := checkListenerControls(ctx, label, func(got context.Context, protocol string, port int) (bool, error) {
					if got != ctx {
						t.Fatal("context replaced")
					}
					calls = append(calls, fmt.Sprintf("%s/%d", protocol, port))
					if port == 18081 {
						return false, cause
					}
					return true, nil
				})
				if !errors.Is(err, cause) || !strings.Contains(err.Error(), label+": tcp/18081:") {
					t.Fatal("listener cause or fixed probe context lost", err)
				}
				if !reflect.DeepEqual(calls, []string{"tcp/18080", "tcp/18081"}) {
					t.Fatal("probe retried or continued", calls)
				}
			})
		}
	}
}

func TestListenerNoEchoRetainsFailedContext(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Time{})
	defer stop()
	for _, ctx := range []context.Context{canceled, expired} {
		for _, label := range []string{"ANDEIVA_NFT_FIXTURE_LISTENER", "ANDEIVA_NFT_FIXTURE_REVERSE_LISTENER"} {
			calls := 0
			err := checkListenerControls(ctx, label, func(context.Context, string, int) (bool, error) { calls++; return false, nil })
			if !errors.Is(err, ctx.Err()) || calls != 1 || !strings.Contains(err.Error(), "no echo response") {
				t.Fatal("failed positive context lost or retried", err, calls)
			}
		}
	}
}

func TestHealthyListenerControlsKeepFixedOrder(t *testing.T) {
	calls := []string{}
	err := checkListenerControls(context.Background(), "ANDEIVA_NFT_FIXTURE_LISTENER", func(_ context.Context, p string, port int) (bool, error) {
		calls = append(calls, fmt.Sprintf("%s/%d", p, port))
		return true, nil
	})
	if err != nil || !reflect.DeepEqual(calls, []string{"tcp/18080", "tcp/18081", "tcp/18082", "udp/18080", "udp/18081", "udp/18082"}) {
		t.Fatal("positive control ordering changed", calls, err)
	}
}

func controlledEcho(t *testing.T, network string, corrupt bool) string {
	t.Helper()
	if network == "udp4" {
		listener, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		release, done := make(chan struct{}), make(chan struct{})
		t.Cleanup(func() { close(release); _ = listener.Close(); <-done })
		go func() {
			defer close(done)
			_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
			payload := make([]byte, 64)
			n, peer, err := listener.ReadFrom(payload)
			if err != nil || n != len(payload) {
				return
			}
			if !corrupt {
				<-release
				return
			}
			payload[0] ^= 1
			_, _ = listener.WriteTo(payload, peer)
		}()
		return listener.LocalAddr().String()
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release); _ = listener.Close(); <-done })
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := make([]byte, 64)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
		if !corrupt {
			<-release
			return
		}
		payload[0] ^= 1
		_, _ = c.Write(payload)
	}()
	return listener.Addr().String()
}

func TestRealNoEchoAndCorruptNonceRemainFailures(t *testing.T) {
	for _, label := range []string{"ANDEIVA_NFT_FIXTURE_LISTENER", "ANDEIVA_NFT_FIXTURE_REVERSE_LISTENER"} {
		for _, network := range []string{"tcp4", "udp4"} {
			for _, corrupt := range []bool{false, true} {
				t.Run(fmt.Sprint(label, "/", network, "/", corrupt), func(t *testing.T) {
					address := controlledEcho(t, network, corrupt)
					calls := 0
					err := checkListenerControls(context.Background(), label, func(_ context.Context, protocol string, _ int) (bool, error) {
						calls++
						if protocol+"4" != network {
							return true, nil
						}
						return exchangeProbe(network, address, nil)
					})
					wantCalls := 1
					if network == "udp4" {
						wantCalls = 4
					}
					if err == nil || calls != wantCalls {
						t.Fatal("negative echo accepted or retried", err, calls)
					}
					want := "no echo response"
					if corrupt {
						want = "ANDEIVA_NFT_PROBE_NONCE_MISMATCH"
					}
					if !strings.Contains(err.Error(), want) {
						t.Fatal("negative echo cause lost", err)
					}
					if !strings.Contains(err.Error(), strings.TrimSuffix(network, "4")+"/18080") {
						t.Fatal("probe direction context changed", err)
					}
				})
			}
		}
	}
}

func TestProbeResultChild(t *testing.T) {
	switch os.Getenv("ANDEIVA_NFT_PROBE_RESULT_TEST") {
	case "10":
		os.Exit(10)
	case "7":
		os.Exit(7)
	case "wait":
		fmt.Println("ready")
		time.Sleep(time.Minute)
	}
}

func probeResultChild(ctx context.Context, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProbeResultChild$")
	cmd.Env = append(os.Environ(), "ANDEIVA_NFT_PROBE_RESULT_TEST="+mode)
	return cmd
}

func TestProbeCommandResultPreservesRealContextAndExit(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint("deadline/", deadline), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := probeResultChild(ctx, "wait")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || line != "ready\n" {
				t.Fatal("child did not become ready", err)
			}
			if !deadline {
				cancel()
			}
			exit := cmd.Wait()
			waited = true
			ok, err := probeCommandResult(ctx, exit, "bounded diagnostic")
			var ended *exec.ExitError
			if ok || !errors.Is(err, ctx.Err()) || !errors.As(err, &ended) || !errors.Is(err, exit) {
				t.Fatal("failed command context or child cause lost", err)
			}
			positive := checkListenerControls(ctx, "ANDEIVA_NFT_FIXTURE_REVERSE_LISTENER", func(context.Context, string, int) (bool, error) { return ok, err })
			if !errors.Is(positive, ctx.Err()) || !errors.Is(positive, exit) {
				t.Fatal("reverse wrapper lost real command cause", positive)
			}
		})
	}
}

func TestProbeCommandResultKeepsExitProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	exit10 := probeResultChild(ctx, "10").Run()
	var ended *exec.ExitError
	if !errors.As(exit10, &ended) || ended.ExitCode() != 10 {
		t.Fatal(exit10)
	}
	cancel()
	if ok, err := probeCommandResult(ctx, exit10, ""); ok || err != nil {
		t.Fatal("exit10 protocol changed", ok, err)
	}
	if ok, err := probeCommandResult(ctx, nil, ""); !ok || err != nil {
		t.Fatal("successful child protocol changed", ok, err)
	}
	ctx7, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	exit7 := probeResultChild(ctx7, "7").Run()
	if ok, err := probeCommandResult(context.Background(), exit7, ""); ok || !errors.Is(err, exit7) {
		t.Fatal("child failure hidden", ok, err)
	}
}
