package previewruntime

import (
	"errors"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

func TestNativeDHCPJobsCloseTraceV4AfterCloseOnly(t *testing.T) {
	var logs nativeLogV3
	line := "ANDEIVA_NATIVE_DHCP_RPC {\"side\":\"helper\",\"verb\":\"dhcp_open\",\"error\":\"recovery\",\"context\":\"ok\"}\n"
	_, _ = logs.Write([]byte(line))
	failure := errors.New("private close detail")
	called := 0
	trace, err := nativeDHCPJobsCloseTraceV4(&logs, func() error {
		called++
		_, _ = logs.Write([]byte("private unrelated output\n" + line))
		_, _ = logs.Write([]byte("ANDEIVA_NATIVE_DHCP_RPC {\"side\":\"helper\",\"verb\":\"dhcp_open\",\"error\":\"recovery\",\"context\":\"ok\",\"payload\":\"private\"}\n"))
		_, _ = logs.Write([]byte("ANDEIVA_NATIVE_DHCP_RPC {\"side\":\"private\",\"verb\":\"dhcp_open\",\"error\":\"recovery\",\"context\":\"ok\"}\n"))
		return failure
	})
	if called != 1 || !errors.Is(err, failure) || trace != line || strings.Contains(trace, "private") {
		t.Fatal("close output replayed, unfiltered or lost its error")
	}
}

func TestNativeDHCPJobsCloseTraceV4BoundAndEmpty(t *testing.T) {
	var logs nativeLogV3
	trace, err := nativeDHCPJobsCloseTraceV4(&logs, func() error { return nil })
	if err != nil || trace != "" {
		t.Fatal("no diagnostic records must emit nothing")
	}
	line := "ANDEIVA_NATIVE_DHCP_RPC {\"side\":\"helper\",\"verb\":\"dhcp_withdraw\",\"error\":\"recovery\",\"context\":\"ok\"}\n"
	trace, err = nativeDHCPJobsCloseTraceV4(&logs, func() error {
		_, e := logs.Write([]byte(strings.Repeat(line, 100)))
		return e
	})
	if err != nil || strings.Count(trace, "\n") != 64 || len(trace) > 32<<10 || !strings.Contains(trace, `"dropped":37`) {
		t.Fatal("unbounded teardown trace")
	}
}

func TestNativeDHCPJobsCloseTraceV4StageSchema(t *testing.T) {
	var logs nativeLogV3
	line := "ANDEIVA_NATIVE_DHCP_RPC {\"side\":\"helper_stage\",\"stage\":\"open_gate_stage\",\"error\":\"recovery\",\"context\":\"ok\"}\n"
	trace, err := nativeDHCPJobsCloseTraceV4(&logs, func() error {
		_, e := logs.Write([]byte(line + strings.ReplaceAll(line, "open_gate_stage", "private-stage")))
		return e
	})
	want := ""
	if firewallipc.KnownRoutedDHCPFailureStageV1("open_gate_stage") {
		want = line
	}
	if err != nil || trace != want {
		t.Fatal("stage schema was not fixed or default emitted diagnostics")
	}
}
