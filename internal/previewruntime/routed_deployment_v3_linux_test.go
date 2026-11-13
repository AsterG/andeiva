//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func deploymentFixtureV3() routedDeploymentRecordV3 {
	ids := Identities{SchemaVersion: 1, APIUID: 1001, APIGID: 1002, HelperUID: 1003, IPCGID: 1004}
	record := routedDeploymentRecordV3{Version: 1, NamespaceProfile: "host-gateway-v2", Identities: ids, AccountsSHA256: strings.Repeat("a", 64), WriteBudget: routedWriteBudgetV3{Bytes: 1 << 30, Inodes: 32768}, ReadBudget: routedReadBudgetV3{Entries: 20000, Objects: 16000, Edges: 200000, IOCalls: 2000000, Bytes: 256 << 20, ActiveBytes: 16 << 20, Depth: 128}}
	for i := 0; i < 4; i++ {
		record.Access = append(record.Access, routedAccessRecordV3{Version: 1, OwnerUID: ids.APIUID, ReaderGID: 1005, Device: 1, Inode: uint64(100 + i)})
	}
	roles := []recoveryreserve.RoleV2{recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2}
	capacities := []int{4096, 16384, 8192}
	for i := range roles {
		record.Profiles = append(record.Profiles, routedProfileRecordV3{ID: fmt.Sprintf("%032x", i+1), Role: roles[i], Slots: 18, Capacity: capacities[i]})
	}
	return record
}

func TestRoutedDeploymentV3StrictDescriptor(t *testing.T) {
	record := deploymentFixtureV3()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRoutedDeploymentV3(data, record.Identities)
	if err != nil || len(decoded.Access) != 4 || decoded.ReadBudget.budget().ActiveBytes != 16<<20 {
		t.Fatal(decoded, err)
	}
	for _, mutate := range []func(*routedDeploymentRecordV3){
		func(r *routedDeploymentRecordV3) { r.Version = 2 }, func(r *routedDeploymentRecordV3) { r.NamespaceProfile = "" }, func(r *routedDeploymentRecordV3) { r.NamespaceProfile = "lab-four-namespaces" }, func(r *routedDeploymentRecordV3) { r.AccountsSHA256 = "" },
		func(r *routedDeploymentRecordV3) { r.WriteBudget.Bytes = 0 }, func(r *routedDeploymentRecordV3) { r.ReadBudget.Depth = 0 },
		func(r *routedDeploymentRecordV3) { r.Access = r.Access[:3] }, func(r *routedDeploymentRecordV3) { r.Access = append(r.Access, r.Access[0]) },
		func(r *routedDeploymentRecordV3) { r.Access[1] = r.Access[0] }, func(r *routedDeploymentRecordV3) { r.Access[0].ReaderGID = r.Identities.APIGID },
		func(r *routedDeploymentRecordV3) { r.Access[0].OwnerUID = r.Identities.HelperUID }, func(r *routedDeploymentRecordV3) { r.Access[0].Inode = 0 },
		func(r *routedDeploymentRecordV3) { r.Profiles = r.Profiles[:2] }, func(r *routedDeploymentRecordV3) { r.Profiles = append(r.Profiles, r.Profiles[0]) },
		func(r *routedDeploymentRecordV3) { r.Profiles[0].Slots = 17 }, func(r *routedDeploymentRecordV3) { r.Profiles[0].Capacity = 8192 },
		func(r *routedDeploymentRecordV3) { r.Profiles[0].Role = recoveryreserve.PlanV2 }, func(r *routedDeploymentRecordV3) { r.Profiles[1].ID = r.Profiles[0].ID },
	} {
		changed := deploymentFixtureV3()
		mutate(&changed)
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRoutedDeploymentV3(raw, record.Identities); err == nil {
			t.Fatal("invalid descriptor accepted", string(raw))
		}
	}
	for _, raw := range [][]byte{append(data, []byte(" {}")...), []byte(strings.Replace(string(data), "\"version\":1", "\"Version\":1", 1)), []byte(strings.Replace(string(data), "\"version\":1", "\"version\":1,\"version\":1", 1)), []byte(strings.Repeat(" ", 16385)), []byte(strings.Replace(string(data), "\"version\":1", "\"version\":1,\"path\":\"/caller\"", 1))} {
		if _, err := decodeRoutedDeploymentV3(raw, record.Identities); err == nil {
			t.Fatal("ambiguous/unbounded descriptor accepted")
		}
	}
}

func TestRoutedDeploymentV3NamespacePinsAreTyped(t *testing.T) {
	inode, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	file, err := openRoutedNamespacePinV3("/proc/self/ns/net", inode)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if file, err := openRoutedNamespacePinV3("/proc/self/ns/net", inode+1); err == nil || file != nil {
		t.Fatal("wrong namespace inode accepted")
	}
	path := filepath.Join(t.TempDir(), "ordinary")
	if err := os.WriteFile(path, []byte("not a namespace"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := openRoutedNamespacePinV3(path, inode); err == nil || file != nil {
		t.Fatal("regular file became namespace authority")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := openRoutedNamespacePinV3(fifo, inode); err == nil || file != nil {
		t.Fatal("FIFO became namespace authority")
	}
	if resources, err := openRoutedDeploymentV3(nil, applianceConfigFixtureV3()); err == nil || resources != nil {
		t.Fatal("missing trusted context opened deployment")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if resources, err := openRoutedDeploymentV3(ctx, applianceConfigFixtureV3()); err == nil || resources != nil {
		t.Fatal("cancelled context opened deployment")
	}
}

func TestRoutedDeploymentV3HealthSocketUsesSeparateLifetime(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	audit, err := openAuditBounded(privateDir(t), uid, gid, 128, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	dir := privateDir(t)
	path := filepath.Join(dir, "grouped-health.sock")
	retained := filepath.Join(dir, "legacy-resource")
	if err := os.WriteFile(retained, []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	observer := &observedHealth{value: firewalladmin.Observation{Hash: "observed", Phase: "idle"}}
	stop, err := startHealthAtV3(context.Background(), path, Identities{APIUID: uid, APIGID: gid}, observer, audit)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("{\"version\":1,\"operation\":\"health\"}\n")); err != nil {
		t.Fatal(err)
	}
	var result HealthResult
	if err := json.NewDecoder(conn).Decode(&result); err != nil || !result.Available {
		t.Fatal(result, err)
	}
	stop()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("health socket retained", err)
	}
	if got, err := os.ReadFile(retained); err != nil || string(got) != "retained" {
		t.Fatal("unrelated runtime resource changed", err)
	}
}
