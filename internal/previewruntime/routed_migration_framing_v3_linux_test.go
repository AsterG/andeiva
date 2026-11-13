//go:build linux

package previewruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/AsterG/andeiva/internal/configpoc"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRoutedMigrationPrepareV3SingleLineBinding(t *testing.T) {
	for _, value := range []any{migrationPrepareRequestV3{Version: 1, Draft: []byte("draft\n"), Authorization: []byte("grant\n")}, migrationPrepareFrameV3{Version: 1, Sequence: 1, Kind: "verify", Request: strings.Repeat("a", 64)}} {
		encoded := migrationPrepareLineV3(value)
		reader := bufio.NewReader(bytes.NewReader(encoded))
		line, e := reader.ReadSlice('\n')
		if e != nil || !bytes.Equal(line, encoded) || bytes.Count(encoded, []byte{'\n'}) != 1 {
			t.Fatal("request/frame bytes differ at pipe boundary")
		}
		if extra, e := reader.ReadSlice('\n'); e != io.EOF || len(extra) != 0 {
			t.Fatal("extra control frame")
		}
		if sha256.Sum256(encoded) != sha256.Sum256(line) {
			t.Fatal("request binding changed")
		}
	}
}
func TestRoutedMigrationPrepareV3ProxyUsesExactWireDigest(t *testing.T) {
	if os.Getenv("ANDEIVA_TEST_PREPARE_WIRE_V3") == "child" {
		proxy := &migrationPrepareProxyV3{reader: bufio.NewReader(os.Stdin), session: strings.Repeat("a", 64)}
		// This fixture is actual pipe framing only; it performs no privileged
		// source verification or namespace/storage operation.
		e := proxy.VerifyMigratedSources(context.Background(), [2]configpoc.LegacyFingerprintV2{}, configpoc.Revision{}, configpoc.Revision{})
		if e != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	command := exec.CommandContext(ctx, self, "-test.run=^TestRoutedMigrationPrepareV3ProxyUsesExactWireDigest$")
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "GOMAXPROCS=2", "ANDEIVA_TEST_PREPARE_WIRE_V3=child"}
	input, e := command.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	output, e := command.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	defer output.Close()
	if e = command.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	line, e := reader.ReadSlice('\n')
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodeMigrationPrepareFrameV3(line, 1, strings.Repeat("a", 64)); e != nil {
		t.Fatal(e)
	}
	digest := sha256.Sum256(line)
	if e = json.NewEncoder(input).Encode(migrationPrepareAckV3{Version: 1, Sequence: 1, Request: hex.EncodeToString(digest[:])}); e != nil {
		t.Fatal(e)
	}
	_ = input.Close()
	if extra, e := reader.ReadSlice('\n'); e != io.EOF || len(extra) != 0 {
		t.Fatal("hidden second frame", len(extra), e)
	}
	if e = command.Wait(); e != nil {
		t.Fatal("producer did not hash the actual single wire frame", e)
	}
}
