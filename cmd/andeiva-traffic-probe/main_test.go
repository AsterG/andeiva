package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/trafficprobe"
)

func TestCLIRejectsUnsafeInputsWithoutEchoingThem(t *testing.T) {
	base := []string{"--authorized-lab", "--mode", "tcp", "--source-ipv4", "127.0.0.1", "--target-ipv4", "127.0.0.1", "--port", "9"}
	for _, suffix := range [][]string{{"--url", "http://user:SECRET@127.0.0.1/?token=SECRET"}, {"--timeout", "20s"}, {"--port", "0"}, {"--port", "65536"}, {"--target-ipv4", "127.1"}, {"--unknown-SECRET"}, {"SECRET_POSITIONAL"}} {
		var output bytes.Buffer
		args := append(append([]string{}, base...), suffix...)
		if exit := run(context.Background(), args, &output); exit != 2 {
			t.Fatalf("invalid arguments exit=%d", exit)
		}
		if strings.Contains(output.String(), "SECRET") {
			t.Fatal("raw arguments leaked")
		}
		var result trafficprobe.Result
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Outcome != "invalid_configuration" {
			t.Fatalf("invalid response: %s %v", output.String(), err)
		}
	}
}

func TestCLIRequiresExplicitLabAcknowledgement(t *testing.T) {
	var output bytes.Buffer
	if exit := run(context.Background(), []string{"--mode", "tcp", "--source-ipv4", "127.0.0.1", "--target-ipv4", "127.0.0.1", "--port", "9"}, &output); exit != 2 {
		t.Fatalf("lab acknowledgement missing, exit=%d", exit)
	}
}

func TestCLIHelp(t *testing.T) {
	for _, language := range []string{"en", "es", "pt"} {
		var output bytes.Buffer
		if exit := run(context.Background(), []string{"--lang", language, "--help"}, &output); exit != 0 || !strings.Contains(output.String(), "--authorized-lab") || !strings.Contains(output.String(), help[language]) {
			t.Fatalf("bad help: %d %s", exit, output.String())
		}
	}
}
