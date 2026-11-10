//go:build linux

package localruntime

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localchannel"
	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/localhttps"
	"github.com/AsterG/andeiva/internal/locallistener"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/localssh"
	"github.com/AsterG/andeiva/internal/localtransport"
	"github.com/AsterG/andeiva/internal/nftfixture"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/previewruntime"
	"golang.org/x/crypto/ssh"
)

type event struct {
	Event      string `json:"event"`
	Phase      string `json:"phase,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
}
type events struct {
	mu  sync.Mutex
	out io.Writer
}

func (e *events) emit(v event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return json.NewEncoder(e.out).Encode(v)
}

func readBootstrap(fd uintptr, out any) error {
	f := os.NewFile(fd, "bootstrap")
	if f == nil {
		return ErrUnavailable
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxBootstrap+1))
	if e != nil || len(b) > maxBootstrap || firewallipc.Decode(b, out) != nil {
		return ErrUnavailable
	}
	return nil
}
func socket(fd uintptr) (net.Conn, error) {
	f := os.NewFile(fd, "private-channel")
	if f == nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	return net.FileConn(f)
}
func inheritedListener(fd uintptr, want string) (net.Listener, error) {
	f := os.NewFile(fd, "recovery")
	if f == nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	l, e := net.FileListener(f)
	if e != nil {
		return nil, e
	}
	if l.Addr().Network() != "tcp" || l.Addr().String() != want {
		_ = l.Close()
		return nil, ErrUnavailable
	}
	return l, nil
}

func compile(c configpoc.Config) (string, error) {
	if c.DefaultAction != "deny" || len(c.Rules) != 0 {
		return "", ErrUnavailable
	}
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: nftfixture.LocalInventory(), Services: []localpolicy.Service{}}
	if c.LocalServices != nil {
		local = *c.LocalServices
	}
	a, e := localnft.CompileWithNeighbors(local, nftfixture.LocalNeighbors())
	if e != nil {
		return "", e
	}
	return a.Digest, nil
}

type backendGate struct {
	service atomic.Pointer[localadmin.Service]
}

func (g *backendGate) Execute(c context.Context, p localadmin.Context, r localadmin.Request) (configpoc.Snapshot, error) {
	if s := g.service.Load(); s != nil {
		return s.Execute(c, p, r)
	}
	return configpoc.Snapshot{}, ErrUnavailable
}
func (g *backendGate) Status(c context.Context, p localadmin.Context) (localadmin.Status, error) {
	if s := g.service.Load(); s != nil {
		return s.Status(c, p)
	}
	return localadmin.Status{}, ErrUnavailable
}
func (g *backendGate) Effective(c context.Context, p localadmin.Context, f localadmin.Filter) (localadmin.Effective, error) {
	if s := g.service.Load(); s != nil {
		return s.Effective(c, p, f)
	}
	return localadmin.Effective{}, ErrUnavailable
}
func (g *backendGate) History(p localadmin.Context, b uint64, l int) ([]configpoc.RevisionEntry, error) {
	if s := g.service.Load(); s != nil {
		return s.History(p, b, l)
	}
	return nil, ErrUnavailable
}
func (g *backendGate) Audit(p localadmin.Context) ([]configpoc.Audit, error) {
	if s := g.service.Load(); s != nil {
		return s.Audit(p)
	}
	return nil, ErrUnavailable
}
func (g *backendGate) IssueProof(p localadmin.Context, r localadmin.ProofRequest) (localadmin.Proof, error) {
	if s := g.service.Load(); s != nil {
		return s.IssueProof(p, r)
	}
	return localadmin.Proof{}, ErrUnavailable
}

type observer struct{ client *firewallipc.Client }

func (o observer) Observe(ctx context.Context) (localadmin.ObservedState, error) {
	r, e := o.client.Observe(ctx)
	if e != nil || r.Local == nil {
		return localadmin.ObservedState{}, ErrUnavailable
	}
	return localadmin.ObservedState{Hash: r.Hash, Local: *r.Local}, nil
}

func helperProcess(parent context.Context, run string, host uint64, supervisor int, out io.Writer) error {
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid <= 0 || uint64(uid) > 2147483647 || uint64(gid) > 2147483647 {
		return ErrUnavailable
	}
	if nftfixture.GuardLocalHelper(host, supervisor, uint32(uid), uint32(gid)) != nil {
		return ErrUnavailable
	}
	var launch launch
	if readBootstrap(7, &launch) != nil || !launch.valid() || launch.Host != host || launch.Binding.Run != run || launch.IDs.HelperUID != uint32(uid) || launch.IDs.HelperGID != uint32(gid) {
		return ErrUnavailable
	}
	tx, e := socket(4)
	if e != nil {
		return e
	}
	defer tx.Close()
	worker, e := socket(5)
	if e != nil {
		return e
	}
	defer worker.Close()
	collector, e := socket(6)
	if e != nil {
		return e
	}
	defer collector.Close()
	w, e := localchannel.New(worker, launch.Binding, false)
	if e != nil {
		return e
	}
	defer w.Close()
	c, e := localchannel.New(collector, launch.Binding, true)
	if e != nil {
		return e
	}
	defer c.Close()
	listeners, e := localchannel.NewListeners(w, c)
	if e != nil {
		return e
	}
	transport, e := localtransport.New(launch.Binding.Namespace, host)
	if e != nil {
		return e
	}
	engine, e := localengine.New(transport, listeners, nftfixture.LocalInventory(), nftfixture.LocalNeighbors())
	if e != nil {
		return e
	}
	guardian := nftguardian.NewRestricted(engine)
	defer guardian.Close()
	session, e := previewruntime.NewLocalSession(launch.Binding.Run, launch.Binding.Namespace, engine, guardian, compile, func(ctx context.Context) (string, localpolicy.Observation, error) {
		v, e := engine.Observe(ctx)
		return v.Hash, v.Local, e
	})
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = tx.Close() })
	defer stop()
	log := &events{out: out}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s := guardian.Status()
				if log.emit(event{Event: "helper", Phase: s.Phase}) != nil || s.Phase == "blocked" {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	scan := bufio.NewScanner(tx)
	scan.Buffer(make([]byte, 4096), firewallipc.MaxFrame)
	for scan.Scan() {
		var m firewallipc.Message
		if firewallipc.Decode(scan.Bytes(), &m) != nil {
			return ErrUnavailable
		}
		r, e := session.Handle(ctx, m)
		if e != nil {
			return e
		}
		b, e := json.Marshal(r)
		if e != nil || len(b) > firewallipc.LocalReplyMaxFrame {
			return ErrUnavailable
		}
		if _, e = tx.Write(append(b, '\n')); e != nil {
			return ErrUnavailable
		}
	}
	return ErrUnavailable
}

func apiProcess(parent context.Context, host uint64, supervisor int, out io.Writer) (result error) {
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid <= 0 || uint64(uid) > 2147483647 || uint64(gid) > 2147483647 {
		return ErrUnavailable
	}
	if nftfixture.GuardLocalAPI(host, supervisor, uint32(uid), uint32(gid)) != nil {
		return ErrUnavailable
	}
	var launch launch
	if readBootstrap(8, &launch) != nil || !launch.valid() || launch.Host != host || launch.IDs.APIUID != uint32(uid) || launch.IDs.APIGID != uint32(gid) {
		return ErrUnavailable
	}
	if directory(launch.Directory, 0, launch.IDs.APIGID, 0750) != nil {
		return ErrUnavailable
	}
	lan, e := inheritedListener(4, net.JoinHostPort(launch.Config.LANAddress, strconv.Itoa(RecoveryPort)))
	if e != nil {
		return e
	}
	defer lan.Close()
	loop, e := inheritedListener(5, "127.0.0.1:"+strconv.Itoa(RecoveryPort))
	if e != nil {
		return e
	}
	defer loop.Close()
	tx, e := socket(6)
	if e != nil {
		return e
	}
	defer tx.Close()
	worker, e := socket(7)
	if e != nil {
		return e
	}
	defer worker.Close()
	read := func(name string) ([]byte, error) {
		return readFile(launch.Directory, name, 0, launch.IDs.APIGID, 0440, maxBootstrap)
	}
	b, e := read("accounts.json")
	var accounts []adminauth.Account
	if e != nil || firewallipc.Decode(b, &accounts) != nil {
		return ErrUnavailable
	}
	audit, e := openAudit(launch.Directory, launch.IDs)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, audit.Close()) }()
	auth, e := adminauth.New(accounts, audit.Append)
	if e != nil {
		return e
	}
	cert, e := read("server.crt")
	if e != nil {
		return e
	}
	key, e := read("server.key")
	if e != nil {
		return e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return ErrUnavailable
	}
	hostKey, e := read("host.key")
	if e != nil {
		return e
	}
	signer, e := ssh.ParsePrivateKey(hostKey)
	if e != nil {
		return ErrUnavailable
	}
	assets, e := openAssets(launch.Config.WebRoot)
	if e != nil {
		return e
	}
	defer assets.Close()
	files := http.FileServerFS(assets.FS())
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/local-services" || r.URL.Path == "/effective-policies" || r.URL.Path == "/firewall" {
			copy := r.Clone(r.Context())
			u := *r.URL
			copy.URL = &u
			copy.URL.Path = "/"
			files.ServeHTTP(w, copy)
			return
		}
		files.ServeHTTP(w, r)
	})
	gate := &backendGate{}
	httpsLimits := localhttps.NewLimits()
	sshLimits := localssh.NewLimits()
	manager, e := locallistener.New(nftfixture.LocalInventory(), func(l localpolicy.Listener, hash string) (locallistener.Server, error) {
		switch l.Service {
		case "https":
			return localhttps.New(localhttps.Options{Auth: auth, Backend: gate, Inventory: nftfixture.LocalInventory(), Listener: l, ActivationHash: hash, Certificate: pair, Limits: httpsLimits, Static: static})
		case "ssh":
			return localssh.New(localssh.Options{Auth: auth, Backend: gate, Listener: l, ActivationHash: hash, HostKey: signer, Limits: sshLimits, Audit: audit.Append})
		default:
			return nil, ErrUnavailable
		}
	})
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var servers []*http.Server
	var core *configpoc.Service
	var service *localadmin.Service
	var client *firewallipc.Client
	workerDone := make(chan error, 1)
	go func() { workerDone <- localchannel.Serve(ctx, worker, launch.Binding, manager, nil) }()
	defer func() {
		cancel()
		for _, s := range servers {
			drain, c := context.WithTimeout(context.WithoutCancel(parent), 12*time.Second)
			e := s.Shutdown(drain)
			c()
			if e != nil {
				e = errors.Join(e, s.Close())
			}
			result = errors.Join(result, e)
		}
		result = errors.Join(result, manager.Close())
		if service != nil {
			result = errors.Join(result, service.Close())
		} else if core != nil {
			result = errors.Join(result, core.Close())
		}
		if client != nil {
			result = errors.Join(result, client.Close())
		}
		_ = worker.Close()
		<-workerDone
	}()
	logEvents := &events{out: out}
	if logEvents.emit(event{Event: "worker-ready"}) != nil {
		return ErrUnavailable
	}
	client, e = firewallipc.NewLocal(tx, tx, launch.Binding.Run, uint64(1)<<32, launch.Binding.Namespace, compile)
	if e != nil {
		return e
	}
	boot, e := bootRequired(launch.Directory, launch.IDs, launch.BootID)
	if e != nil {
		return e
	}
	initial := configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", Rules: []configpoc.Rule{}, LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: nftfixture.LocalInventory(), Services: []localpolicy.Service{}}}
	core, e = configpoc.Open(filepath.Join(launch.Directory, "state"), []configpoc.Engine{client}, configpoc.Options{Initial: &initial, Boot: boot})
	if e != nil {
		return e
	}
	if client.Recovered(ctx) != nil {
		return ErrUnavailable
	}
	service, e = localadmin.New(core, localadmin.Options{RunID: launch.Binding.Run, RecoveryEndpointID: recoveryID, Inventory: nftfixture.LocalInventory(), Authority: firewallipc.Authority{Client: client}, Observer: observer{client}})
	if e != nil {
		return e
	}
	if markBoot(launch.Directory, launch.IDs, launch.BootID) != nil {
		return ErrUnavailable
	}
	gate.service.Store(service)
	httpDone := make(chan error, 2)
	budget := newRecoveryBudget()
	for _, l := range []net.Listener{lan, loop} {
		h, e := adminapi.New(adminapi.Options{Origin: "https://" + l.Addr().String(), Auth: auth, Local: gate, LocalEndpointID: recoveryID, LocalRecovery: true, LocalInventory: nftfixture.LocalInventory(), Static: static})
		if e != nil {
			return e
		}
		s := &http.Server{Handler: budget.handler(h), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
		servers = append(servers, s)
		allowed := netip.MustParsePrefix(launch.Config.AllowedCIDR)
		if l == loop {
			allowed = netip.MustParsePrefix("127.0.0.1/32")
		}
		bounded := newRecoveryListener(l, allowed, budget)
		go func() { httpDone <- s.ServeTLS(bounded, "", "") }()
	}
	observed, e := client.Observe(ctx)
	if e != nil || observed.Hash == "" {
		return ErrUnavailable
	}
	snapshot, e := core.Execute(ctx, configpoc.Principal{ID: "runtime", Role: configpoc.RoleAdmin}, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if e != nil || snapshot.RecoveryRequired {
		return ErrUnavailable
	}
	if logEvents.emit(event{Event: "ready", Hash: observed.Hash, Generation: snapshot.Generation}) != nil {
		return ErrUnavailable
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-httpDone:
			return ErrUnavailable
		case err := <-workerDone:
			workerDone <- err
			return ErrUnavailable
		case <-ticker.C:
			if !audit.healthy() {
				return ErrUnavailable
			}
			v, e := client.Observe(ctx)
			if e != nil {
				return ErrUnavailable
			}
			state, e := core.Execute(ctx, configpoc.Principal{ID: "runtime", Role: configpoc.RoleAdmin}, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
			if e != nil || state.RecoveryRequired {
				return ErrUnavailable
			}
			if logEvents.emit(event{Event: "observed", Hash: v.Hash, Generation: state.Generation}) != nil {
				return ErrUnavailable
			}
		}
	}
}
