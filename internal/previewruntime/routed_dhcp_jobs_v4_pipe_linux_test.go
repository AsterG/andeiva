//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

// Real SCM_RIGHTS, credentials and pipe I/O; the producer is a test peer that
// returns unavailable. It neither acquires DHCP nor invents lease authority.
func transferredJobPipesV4(t *testing.T) (*jobOwnerFixtureV4, []*os.File) {
	t.Helper()
	o := newJobOwnerFixtureV4(t)
	m, work, source := jobSourceFixtureV4(t, o.binding)
	b := &routedDHCPJobBrokerV4{
		preflight: func(context.Context, configpoc.RoutedWorkReferenceV1) (RoutedSelectedPreflightResultV4, error) {
			return source, nil
		},
		prepare: func(context.Context, networkplan.Revision) (routedDHCPJobOwnerV4, error) { return o, nil },
	}
	root, helper, peer := jobChannelFixtureV4(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- b.serve(ctx, root, m, peer) }()
	client := &routedDHCPJobClientV4{conn: helper, metadata: m, peer: peer}
	t.Cleanup(func() { _ = client.Close(); cancel(); <-done })
	_, files, err := client.call(ctx, "prepare", work)
	if err != nil || len(files) != 4 {
		t.Fatal("SCM client prepare", err)
	}
	t.Cleanup(func() {
		for _, file := range files {
			_ = file.Close()
		}
	})
	return o, files
}

func TestRoutedDHCPJobsV4TransferredPipeDeadlines(t *testing.T) {
	_, files := transferredJobPipesV4(t)
	deadline := time.Now().Add(time.Second)
	if err := files[0].SetWriteDeadline(deadline); err != nil {
		t.Fatal("transferred request pipe cannot support Current deadline", err)
	}
	if err := files[1].SetReadDeadline(deadline); err != nil {
		t.Fatal("transferred reply pipe cannot support Current deadline", err)
	}
}

func TestRoutedDHCPJobsV4TransferredCurrentUnavailableKeepsOwner(t *testing.T) {
	o, files := transferredJobPipesV4(t)
	reader, err := newRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4{files[0], files[1], files[2]}, o.binding, func() bool { return routedDHCPOwnerPIDFDAliveV3(files[2], os.Getpid()) }, func() (int64, error) { return int64(time.Second), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		scan := routedDHCPOwnerScannerV3(o.others[0])
		for sequence := uint64(1); sequence <= 2; sequence++ {
			if !scan.Scan() {
				done <- errors.New("producer lost Current request pipe")
				return
			}
			var request routedDHCPOwnerRequestV3
			if routedDHCPOwnerDecodeV3(scan.Bytes(), &request) != nil || request.Version != 4 || request.Sequence != sequence || request.Incarnation != o.binding.Owner.Incarnation || request.Operation != "current" {
				done <- ErrIdentity
				return
			}
			if err := routedDHCPOwnerWriteV3(o.others[1], routedDHCPDeferredReplyV4{Version: 4, Incarnation: request.Incarnation, Sequence: sequence, Unavailable: true}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		grant, err := reader.Current(ctx)
		if !errors.Is(err, ErrUnavailable) || grant != (RoutedDHCPOwnerFactV3{}) || reader.reader.dead || o.closed.Load() != 0 {
			t.Fatal("waiting for initial lease closed producer or granted authority", err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRoutedDHCPJobsV4TransferredCurrentCancellation(t *testing.T) {
	o, files := transferredJobPipesV4(t)
	reader, err := newRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4{files[0], files[1], files[2]}, o.binding, func() bool { return routedDHCPOwnerPIDFDAliveV3(files[2], os.Getpid()) }, func() (int64, error) { return int64(time.Second), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	requestSeen, eof := make(chan bool, 1), make(chan bool, 1)
	go func() {
		scan := routedDHCPOwnerScannerV3(o.others[0])
		requestSeen <- scan.Scan()
		eof <- !scan.Scan()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := reader.Current(ctx); done <- err }()
	select {
	case seen := <-requestSeen:
		if !seen {
			t.Fatal("request pipe closed before cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Current never sent request")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnavailable) || !reader.reader.dead {
			t.Fatal("cancelled Current remained usable", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Current deadline could not interrupt real pipe read")
	}
	select {
	case closed := <-eof:
		if !closed {
			t.Fatal("cancelled reader left request capability open")
		}
	case <-time.After(time.Second):
		t.Fatal("producer did not observe closed reader")
	}
}

func TestRoutedDHCPJobsV4PipeAdoptionOwnershipAndReferences(t *testing.T) {
	for _, kind := range []string{"valid", "uid", "gid", "mode", "access", "type"} {
		t.Run(kind, func(t *testing.T) {
			o := newJobOwnerFixtureV4(t)
			files := []*os.File{o.files.Request, o.files.Reply, o.files.ProducerPIDFD}
			t.Cleanup(func() {
				for _, file := range files {
					_ = file.Close()
				}
			})
			peer := routedDHCPJobPeerV4{pid: os.Getpid(), uid: uint32(os.Geteuid()), gid: uint32(os.Getegid())}
			first, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", files[0].Fd()))
			if err != nil {
				t.Fatal(err)
			}
			second, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", files[1].Fd()))
			if err != nil {
				t.Fatal(err)
			}
			beforeFirst, beforeSecond := jobDescriptorReferencesV4(t, first), jobDescriptorReferencesV4(t, second)
			pidfd := files[2]
			beforeFlags, err := unix.FcntlInt(pidfd.Fd(), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "uid":
				peer.uid ^= 1
			case "gid":
				peer.gid ^= 1
			case "mode":
				if err = files[0].Chmod(0644); err != nil {
					t.Fatal(err)
				}
			case "access":
				files[0], files[1] = files[1], files[0]
			case "type":
				files[0] = pidfd
			}
			err = adoptRoutedDHCPJobPipesV4(files, peer)
			if (err == nil) != (kind == "valid") {
				t.Fatal("pipe validation", kind, err)
			}
			if jobDescriptorReferencesV4(t, first) != beforeFirst || jobDescriptorReferencesV4(t, second) != beforeSecond {
				t.Fatal("pipe adoption leaked or lost a reference")
			}
			afterFlags, e := unix.FcntlInt(pidfd.Fd(), unix.F_GETFL, 0)
			if e != nil || files[2] != pidfd || afterFlags != beforeFlags {
				t.Fatal("adoption modified pidfd", e)
			}
			if kind == "valid" {
				if files[0].SetWriteDeadline(time.Now().Add(time.Second)) != nil || files[1].SetReadDeadline(time.Now().Add(time.Second)) != nil {
					t.Fatal("adopted pipe missing deadline support")
				}
			}
		})
	}
}

func TestRoutedDHCPJobsV4ProductionPeerRemainsRoot(t *testing.T) {
	root, _, _ := jobChannelFixtureV4(t)
	f := routedLaunchFilesV3{jobs: root}
	c := f.context(routedLaunchBootstrapV3{DHCPJobs: true, ParentPID: os.Getpid(), Identities: Identities{HelperUID: 1234, APIGID: 5678}})
	if c.dhcpJobs == nil || c.dhcpJobs.peer.pid != os.Getpid() || c.dhcpJobs.peer.uid != 0 || c.dhcpJobs.peer.gid != 0 {
		t.Fatal("production bootstrap accepted configurable owner credentials")
	}
}

func TestRoutedDHCPJobsV4RejectsInvalidTransferredPipeWithoutLeak(t *testing.T) {
	for _, kind := range []string{"type", "access", "binding"} {
		t.Run(kind, func(t *testing.T) {
			o := newJobOwnerFixtureV4(t)
			m, work, _ := jobSourceFixtureV4(t, o.binding)
			root, helper, peer := jobChannelFixtureV4(t)
			service, id, e := o.RetainedServicePin()
			if e != nil {
				t.Fatal(e)
			}
			defer service.Close()
			version := 1
			files := []*os.File{o.files.Request, o.files.Reply, o.files.ProducerPIDFD, service}
			if kind == "type" {
				f, err := os.CreateTemp(t.TempDir(), "not-a-pipe")
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				files[1] = f
			} else if kind == "access" {
				files[1] = o.files.Request
			}
			target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", files[0].Fd()))
			if err != nil {
				t.Fatal(err)
			}
			baseline := jobDescriptorReferencesV4(t, target)
			flags, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			sent := make(chan error, 1)
			go func() {
				var request routedDHCPJobV4
				rights, err := routedDHCPJobReceiveV4(root, peer, &request)
				for _, f := range rights {
					_ = f.Close()
				}
				if err != nil {
					sent <- err
					return
				}
				binding := o.binding
				if kind == "binding" {
					binding.Version = 3
				}
				sent <- routedDHCPJobSendV4(root, routedDHCPJobReplyV4{Job: request, Binding: &binding, ServiceCgroupVersion: &version, ServiceCgroupIdentity: &id}, files)
			}()
			client := &routedDHCPJobClientV4{conn: helper, metadata: m, peer: peer}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			out, received, err := client.call(ctx, "prepare", work)
			if err == nil || len(received) != 0 || out.Binding != nil || !client.failed {
				t.Fatal("invalid transferred capability accepted", err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			if jobDescriptorReferencesV4(t, target) != baseline {
				t.Fatal("rejected rights leaked")
			}
			after, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFL, 0)
			if err != nil || after != flags {
				t.Fatal("invalid transfer changed pipe flags", err)
			}
		})
	}
}
