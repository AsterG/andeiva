//go:build linux

package recoveryreserve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type nativeReaderIdentityFixtureV2 struct {
	PrivatePath string
	Path        string
	Access      ReaderAccessV2
	Profile     ProfileV2
	Binding     BindingV2
}

// This test changes credentials only in disposable child processes. It never
// creates accounts, touches live stores or runs privileged network operations.
func TestNativeReadOnlyV2ThreeIdentities(t *testing.T) {
	if os.Getenv("ANDEIVA_READER_IDENTITY_LAB") != "1" {
		t.Skip("requires explicitly authorized isolated Linux lab")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native identity harness requires root to drop child credentials")
	}
	dir, e := os.MkdirTemp("", "andeiva-reader-identities-")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := os.RemoveAll(dir); e != nil {
			t.Error(e)
		}
	}()
	if e = os.Chmod(dir, 0711); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "pool")
	if e = os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(path, 60001, 60002); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, os.ModeSetgid|0750); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil {
		t.Fatal(e)
	}
	st := info.Sys().(*syscall.Stat_t)
	privatePath := filepath.Join(dir, "private-account-fixture")
	if e = os.WriteFile(privatePath, []byte("nonsecret fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(privatePath, 60001, 60001); e != nil {
		t.Fatal(e)
	}
	fixture := nativeReaderIdentityFixtureV2{PrivatePath: privatePath, Path: path, Access: ReaderAccessV2{Version: 1, OwnerUID: 60001, ReaderGID: 60002, Device: st.Dev, Inode: st.Ino}}
	// The child executable is an immutable root-owned fixture reachable through
	// this private test area; the writer/helper cannot replace it.
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	source, e := os.Open(self)
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(dir, "identity.test")
	dest, e := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if e != nil {
		_ = source.Close()
		t.Fatal(e)
	}
	copied, copyErr := io.Copy(dest, io.LimitReader(source, 16<<20+1))
	closeSource, closeDest := source.Close(), dest.Close()
	if copyErr != nil || closeSource != nil || closeDest != nil || copied > 16<<20 {
		t.Fatal("cannot prepare bounded child executable")
	}
	if e = os.Chmod(binary, 0755); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := func(role string, uid, gid uint32, groups []uint32, fixture nativeReaderIdentityFixtureV2) *exec.Cmd {
		t.Helper()
		data, e := json.Marshal(fixture)
		if e != nil {
			t.Fatal(e)
		}
		// The executable is this root-created fixed test binary; caller input is
		// supplied as typed JSON over stdin, never a command string or executable.
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestNativeReaderV2IdentityChild$", "-test.count=1", "-test.timeout=20s")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "ANDEIVA_READER_IDENTITY_CHILD=" + role, "ANDEIVA_READER_IDENTITY_FIXTURE=" + string(data)}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
		return cmd
	}
	writer := child("writer", 60001, 60001, []uint32{60002}, fixture)
	var writerError bytes.Buffer
	writer.Stderr = &writerError
	input, e := writer.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := writer.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = writer.Start(); e != nil {
		t.Fatal(e)
	}
	writerFinished := false
	defer func() {
		_ = input.Close()
		if !writerFinished {
			_ = writer.Process.Kill()
			_ = writer.Wait()
		}
	}()
	decoder := json.NewDecoder(output)
	if e = decoder.Decode(&fixture); e != nil {
		detail, _ := io.ReadAll(io.LimitReader(io.MultiReader(decoder.Buffered(), output), 8192))
		t.Fatalf("writer preparation failed: %v: %s", e, detail)
	}
	for _, identity := range []struct {
		role     string
		uid, gid uint32
		groups   []uint32
	}{{"reader", 60003, 60003, []uint32{60002}}, {"outsider", 60004, 60004, []uint32{}}} {
		command := child(identity.role, identity.uid, identity.gid, identity.groups, fixture)
		if out, e := command.CombinedOutput(); e != nil {
			t.Fatalf("%s identity check failed: %v: %s", identity.role, e, out)
		}
	}
	if _, e = fmt.Fprintln(input, "finish"); e != nil {
		t.Fatal(e)
	}
	_ = input.Close()
	if e = writer.Wait(); e != nil {
		t.Fatalf("writer failed: %v %s", e, writerError.String())
	}
	writerFinished = true
}

func TestNativeReaderV2IdentityChild(t *testing.T) {
	role := os.Getenv("ANDEIVA_READER_IDENTITY_CHILD")
	if role == "" {
		t.Skip("identity child only")
	}
	var f nativeReaderIdentityFixtureV2
	decoder := json.NewDecoder(strings.NewReader(os.Getenv("ANDEIVA_READER_IDENTITY_FIXTURE")))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&f) != nil || !f.Access.valid() || os.Geteuid() == 0 {
		t.Fatal("invalid fixture or child identity")
	}
	if role == "outsider" {
		if os.Geteuid() != 60004 {
			t.Fatal("wrong outsider UID")
		}
		if root, e := os.OpenRoot(f.Path); e == nil {
			defer root.Close()
			if _, e = OpenReadOnlyV2(root, f.Access, f.Profile); e == nil {
				t.Fatal("outsider opened reader")
			}
		}
		if _, e := os.ReadFile(filepath.Join(f.Path, slotName(f.Binding.Claim.Slot))); e == nil {
			t.Fatal("outsider read protected pool")
		}
		return
	}
	root, e := os.OpenRoot(f.Path)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	switch role {
	case "writer":
		if os.Geteuid() != 60001 {
			t.Fatal("wrong writer UID")
		}
		pool, e := PrepareSharedV2(root, 18, 16384, PlanV2, f.Access)
		if e != nil {
			t.Fatal(e)
		}
		defer pool.Close()
		f.Profile, e = pool.Profile()
		if e != nil {
			t.Fatal(e)
		}
		claim, e := pool.ClaimClass("native-reader-bundle", OrdinaryV2)
		if e != nil {
			t.Fatal(e)
		}
		f.Binding, e = pool.WriteOnce(claim, []byte("bounded native identity fixture"), scopeForV2(claim.Owner))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.NewEncoder(os.Stdout).Encode(f); e != nil {
			t.Fatal(e)
		}
		var done string
		if _, e = fmt.Fscan(os.Stdin, &done); e != nil || done != "finish" {
			t.Fatal("writer synchronization failed")
		}
		actual, e := pool.ReadBound(f.Binding)
		if e != nil || string(actual) != "bounded native identity fixture" {
			t.Fatal("reader modified writer data", e)
		}
	case "reader":
		if _, e := os.ReadFile(f.PrivatePath); e == nil {
			t.Fatal("helper read private owner data")
		}
		if _, e := OpenSharedV2(root, f.Access); e == nil {
			t.Fatal("helper obtained writer handle")
		}
		if os.Geteuid() != 60003 {
			t.Fatal("wrong helper UID")
		}
		pool, e := OpenReadOnlyV2(root, f.Access, f.Profile)
		if e != nil {
			t.Fatal(e)
		}
		defer pool.Close()
		snapshot, e := pool.Snapshot(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		actual, e := snapshot.ReadBound(f.Binding)
		if e != nil || string(actual) != "bounded native identity fixture" {
			t.Fatal("read failed", e)
		}
		// Directory and bank checks are actual kernel access checks under the
		// helper UID while a different writer still holds its flock.
		if file, e := root.OpenFile("unauthorized", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); e == nil {
			_ = file.Close()
			t.Fatal("helper created a file")
		}
		if file, e := root.OpenFile(slotName(f.Binding.Claim.Slot), os.O_WRONLY, 0); e == nil {
			_ = file.Close()
			t.Fatal("helper opened a writable bank")
		}
		if e = root.Rename(slotName(f.Binding.Claim.Slot), "renamed"); e == nil {
			t.Fatal("helper renamed a protected file")
		}
		if e = root.Remove(slotName(f.Binding.Claim.Slot)); e == nil {
			t.Fatal("helper removed a protected file")
		}
		if e = pool.Revalidate(context.Background(), snapshot); e != nil {
			t.Fatal("read-only checks changed data", e)
		}
	default:
		t.Fatal("unknown child role")
	}
}
