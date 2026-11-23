//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRoutedDHCPServicePrepareRejectsMissingForeignAndExtraCapabilities(t *testing.T) {
	for _, kind := range []string{"legacy-three", "version-missing", "version-unknown", "identity-missing", "identity-wrong", "regular-file", "path-only", "extra-right"} {
		t.Run(kind, func(t *testing.T) {
			o := newJobOwnerFixtureV4(t)
			m, work, _ := jobSourceFixtureV4(t, o.binding)
			root, helper, peer := jobChannelFixtureV4(t)
			pin, id, e := o.RetainedServicePin()
			if e != nil {
				t.Fatal(e)
			}
			defer pin.Close()
			version := 1
			reply := routedDHCPJobReplyV4{Binding: &o.binding, ServiceCgroupVersion: &version, ServiceCgroupIdentity: &id}
			files := []*os.File{o.files.Request, o.files.Reply, o.files.ProducerPIDFD, pin}
			switch kind {
			case "legacy-three":
				reply.ServiceCgroupVersion = nil
				reply.ServiceCgroupIdentity = nil
				files = files[:3]
			case "version-missing":
				reply.ServiceCgroupVersion = nil
			case "version-unknown":
				version = 2
			case "identity-missing":
				reply.ServiceCgroupIdentity = nil
			case "identity-wrong":
				id.Inode++
			case "regular-file":
				f, e := os.CreateTemp(t.TempDir(), "foreign")
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				files[3] = f
			case "path-only":
				fd, e := unix.Open("/sys/fs/cgroup", unix.O_PATH|unix.O_CLOEXEC, 0)
				if e != nil {
					t.Fatal(e)
				}
				f := os.NewFile(uintptr(fd), "path-only")
				defer f.Close()
				files[3] = f
			case "extra-right":
				files = append(files, pin)
			}
			target, e := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", pin.Fd()))
			if e != nil {
				t.Fatal(e)
			}
			before := jobDescriptorReferencesV4(t, target)
			sent := make(chan error, 1)
			go func() {
				var q routedDHCPJobV4
				rights, e := routedDHCPJobReceiveV4(root, peer, &q)
				for _, f := range rights {
					_ = f.Close()
				}
				if e != nil {
					sent <- e
					return
				}
				reply.Job = q
				if kind == "extra-right" {
					// Deliberately bypass trusted sender limit to exercise the receiver.
					raw, e := json.Marshal(reply)
					if e != nil {
						sent <- e
						return
					}
					var fds []int
					for _, f := range files {
						fds = append(fds, int(f.Fd()))
					}
					_, _, e = root.WriteMsgUnix(raw, unix.UnixRights(fds...), nil)
					sent <- e
					return
				}
				sent <- routedDHCPJobSendV4(root, reply, files)
			}()
			client := &routedDHCPJobClientV4{conn: helper, metadata: m, peer: peer}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			out, received, e := client.call(ctx, "prepare", work)
			for _, f := range received {
				_ = f.Close()
			}
			if e == nil || out != (routedDHCPJobReplyV4{}) || len(received) != 0 || !client.failed {
				t.Fatal("invalid service capability accepted")
			}
			if e = <-sent; e != nil {
				t.Fatal(e)
			}
			if after := jobDescriptorReferencesV4(t, target); after != before {
				t.Fatalf("service pin leaked: %d != %d", after, before)
			}
		})
	}
}

func TestRoutedDHCPServiceActivateStopRejectPrepareMetadata(t *testing.T) {
	for _, op := range []string{"activate", "stop"} {
		for _, kind := range []string{"binding", "version", "identity", "right"} {
			t.Run(op+"/"+kind, func(t *testing.T) {
				o := newJobOwnerFixtureV4(t)
				m, work, _ := jobSourceFixtureV4(t, o.binding)
				root, helper, peer := jobChannelFixtureV4(t)
				pin, id, e := o.RetainedServicePin()
				if e != nil {
					t.Fatal(e)
				}
				defer pin.Close()
				version := 1
				reply := routedDHCPJobReplyV4{}
				var files []*os.File
				switch kind {
				case "binding":
					reply.Binding = &o.binding
				case "version":
					reply.ServiceCgroupVersion = &version
				case "identity":
					reply.ServiceCgroupIdentity = &id
				case "right":
					files = []*os.File{pin}
				}
				sent := make(chan error, 1)
				go func() {
					var q routedDHCPJobV4
					rights, e := routedDHCPJobReceiveV4(root, peer, &q)
					for _, f := range rights {
						_ = f.Close()
					}
					if e != nil {
						sent <- e
						return
					}
					reply.Job = q
					sent <- routedDHCPJobSendV4(root, reply, files)
				}()
				client := &routedDHCPJobClientV4{conn: helper, metadata: m, peer: peer}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				out, received, e := client.call(ctx, op, work)
				for _, f := range received {
					_ = f.Close()
				}
				if e == nil || out != (routedDHCPJobReplyV4{}) || len(received) != 0 {
					t.Fatal("unexpected authority on effect acknowledgement")
				}
				if e = <-sent; e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}
