//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func migrationInetEmptyFixtureV3(name string) []byte {
	remote := "rem_address"
	if strings.HasSuffix(name, "6") {
		remote = "remote_address"
	}
	header := " sl local_address " + remote + " st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"
	if strings.HasPrefix(name, "udp") {
		header += " ref pointer drops"
	}
	return []byte(header + "\n")
}
func migrationInetRowFixtureV3(name, state string) []byte {
	address := "00000000"
	if strings.HasSuffix(name, "6") {
		address = strings.Repeat("0", 32)
	}
	return append(migrationInetEmptyFixtureV3(name), []byte("0: "+address+":01BB "+address+":0000 "+state+" 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 0\n")...)
}
func TestRoutedMigrationInetV3StrictBoundedDualStackProfile(t *testing.T) {
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if migrationInetEmptyV3(name, migrationInetEmptyFixtureV3(name)) != nil {
			t.Fatal("empty valid header refused", name)
		}
		if migrationInetEmptyV3(name, migrationInetRowFixtureV3(name, "0A")) == nil {
			t.Fatal("bound/listening socket accepted", name)
		}
		row := migrationInetRowFixtureV3(name, "01")
		if strings.HasPrefix(name, "tcp") {
			if migrationInetEmptyV3(name, row) != nil {
				t.Fatal("non-listening TCP profile refused", name)
			}
		} else if migrationInetEmptyV3(name, row) == nil {
			t.Fatal("UDP endpoint accepted", name)
		}
		for _, data := range [][]byte{nil, []byte("unknown\n"), []byte(strings.Repeat(" ", migrationProcLimitV3+1)), []byte(strings.TrimSuffix(string(migrationInetEmptyFixtureV3(name)), "\n")), append(migrationInetEmptyFixtureV3(name), []byte("truncated\n")...), []byte(strings.Replace(string(row), " 01 ", " ZZ ", 1))} {
			if migrationInetEmptyV3(name, data) == nil {
				t.Fatal("malformed/truncated proc input accepted", name)
			}
		}
	}
	if _, err := readRoutedMigrationProcV3("/caller/path"); err == nil {
		t.Fatal("caller selected proc path accepted")
	}
	count := 0
	if err := inspectRoutedMigrationInetV3(context.Background(), func(name string) ([]byte, error) { count++; return migrationInetEmptyFixtureV3(name), nil }); err != nil || count != 4 {
		t.Fatal(err, count)
	}
	if inspectRoutedMigrationInetV3(context.Background(), func(string) ([]byte, error) { return nil, errors.New("read failure") }) == nil {
		t.Fatal("read failure interpreted as absence")
	}
}
