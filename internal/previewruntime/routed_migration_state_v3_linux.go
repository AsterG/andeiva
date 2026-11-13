//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

// observeMigrationGuardianV3 has a fixed state/observe/state conversation. A
// normal handshake advances only the controller epoch; Recovered and every
// effect verb are deliberately absent. The returned receipt may be historical:
// idle does not require clearing its original ID, target or deadline.
func observeMigrationGuardianV3(ctx context.Context, m Metadata, ids Identities, expected string) (firewalladmin.LeaseState, int32, error) {
	fail := func() (firewalladmin.LeaseState, int32, error) { return firewalladmin.LeaseState{}, 0, ErrUnavailable }
	if ctx == nil || ctx.Err() != nil || m.Validate() != nil || ids.Validate() != nil || !validHex(expected, 32) || socketInfo(HelperSocket, ids.HelperUID, ids.IPCGID) != nil {
		return fail()
	}
	before, err := os.Lstat(HelperSocket)
	if err != nil {
		return fail()
	}
	dial := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dial.DialContext(ctx, "unix", HelperSocket)
	if err != nil {
		return fail()
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return fail()
	}
	defer conn.Close()
	if peer(conn, ids.HelperUID, ids.IPCGID) != nil {
		return fail()
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fail()
	}
	var credentials *syscall.Ucred
	var inner error
	if err = raw.Control(func(fd uintptr) {
		credentials, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || inner != nil || credentials == nil || credentials.Pid <= 1 || credentials.Uid != ids.HelperUID || credentials.Gid != ids.IPCGID {
		return fail()
	}
	if conn.SetDeadline(time.Now().Add(3*time.Second)) != nil || json.NewEncoder(conn).Encode(hello{Version: 1, RuntimeRun: m.RunID, Namespace: m.GatewayNamespace}) != nil {
		return fail()
	}
	reader := bufio.NewReaderSize(conn, firewallipc.MaxFrame)
	data, err := readFrame(conn, reader, true)
	var greeting hello
	if err != nil || firewallipc.Decode(data, &greeting) != nil || greeting.Version != 1 || greeting.RuntimeRun != m.RunID || !validHex(greeting.Run, 16) || greeting.Namespace != m.GatewayNamespace || greeting.Epoch == 0 || greeting.Epoch > 0xffffffff || reader.Buffered() != 0 || conn.SetDeadline(time.Time{}) != nil {
		return fail()
	}
	client, err := firewallipc.New(conn, conn, greeting.Run, greeting.Epoch<<32, greeting.Namespace, artifactDigest)
	if err != nil {
		return fail()
	}
	defer client.Close()
	state, err := readMigrationGuardianV3(ctx, client, expected)
	if err != nil {
		return fail()
	}
	after, fileErr := os.Lstat(HelperSocket)
	if fileErr != nil || !os.SameFile(before, after) || socketInfo(HelperSocket, ids.HelperUID, ids.IPCGID) != nil || client.Close() != nil || ctx.Err() != nil {
		return fail()
	}
	return state, credentials.Pid, nil
}

// This interface deliberately contains no lease, recovery or apply operations.
type migrationGuardianReadV3 interface {
	State(context.Context) (firewalladmin.LeaseState, error)
	Observe(context.Context) (firewallipc.Reply, error)
}

func readMigrationGuardianV3(ctx context.Context, reader migrationGuardianReadV3, expected string) (firewalladmin.LeaseState, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || !validHex(expected, 32) {
		return firewalladmin.LeaseState{}, ErrUnavailable
	}
	state, err := reader.State(ctx)
	if err != nil || state.Phase != "idle" {
		return firewalladmin.LeaseState{}, ErrUnavailable
	}
	observed, err := reader.Observe(ctx)
	if err != nil || observed.Hash != expected {
		return firewalladmin.LeaseState{}, ErrUnavailable
	}
	final, err := reader.State(ctx)
	if err != nil || final != state || final.Phase != "idle" || ctx.Err() != nil {
		return firewalladmin.LeaseState{}, ErrUnavailable
	}
	return state, nil
}
