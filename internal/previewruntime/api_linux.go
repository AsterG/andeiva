//go:build linux

package previewruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

func API(ctx context.Context, c Config) error {
	if err := LegacyRuntimeAllowedV3(); err != nil {
		return err
	}
	ids, e := LoadIdentities(c)
	if e != nil {
		return e
	}
	if checkPrivileges(ids, false) != nil {
		return ErrIdentity
	}
	m, e := ReadMetadata()
	if e != nil {
		return e
	}
	ns, e := namespaceID("/proc/self/ns/net")
	if e != nil || ns != m.HostNamespace {
		return ErrIdentity
	}
	listener, e := inheritedListener(c)
	if e != nil {
		return e
	}
	defer listener.Close()
	pair, e := loadTLS(c, ids)
	if e != nil {
		return e
	}
	accounts, e := loadAccounts(ids)
	if e != nil {
		return e
	}
	audit, e := openAudit(DataDir+"/audit", ids.APIUID, ids.APIGID)
	if e != nil {
		return e
	}
	defer audit.Close()
	auth, e := adminauth.New(accounts, audit.Append)
	if e != nil {
		return e
	}
	client, e := connectHelper(ctx, m, ids)
	if e != nil {
		return e
	}
	defer client.Close()
	initial := configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	var core *configpoc.Service
	e = recoverBoot(DataDir+"/local", m.BootID, ids.APIUID, ids.APIGID, func(boot bool) error {
		var err error
		core, err = configpoc.Open(filepath.Join(DataDir, "state"), []configpoc.Engine{client}, configpoc.Options{Initial: &initial, Boot: boot})
		if err != nil {
			return err
		}
		if err = client.Recovered(ctx); err != nil {
			err = errors.Join(err, core.Close())
			core = nil
			return err
		}
		return nil
	})
	if e != nil {
		if core != nil {
			e = errors.Join(e, core.Close())
		}
		return e
	}
	service, e := firewalladmin.New(core, firewallipc.Authority{Client: client})
	if e != nil {
		return errors.Join(e, core.Close())
	}
	defer service.Close()
	if safeParents(WebRoot+"/index.html") != nil {
		return ErrStorage
	}
	assets, e := os.OpenRoot(WebRoot)
	if e != nil {
		return ErrStorage
	}
	defer assets.Close()
	if _, e = fs.Stat(assets.FS(), "index.html"); e != nil {
		return ErrStorage
	}
	files := http.FileServerFS(assets.FS())
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/firewall" || r.URL.Path == "/firewall/" {
			copy := r.Clone(r.Context())
			u := *r.URL
			copy.URL = &u
			copy.URL.Path = "/"
			files.ServeHTTP(w, copy)
			return
		}
		files.ServeHTTP(w, r)
	})
	handler, e := adminapi.New(adminapi.Options{FirewallRuleState: true, Origin: c.Origin(), Auth: auth, Backend: service, Static: static, Observe: func(ctx context.Context) (adminapi.Effective, error) {
		r, e := client.Observe(ctx)
		if e != nil {
			return adminapi.Effective{}, e
		}
		out := adminapi.Effective{Revision: r.Hash, CounterEpoch: r.CounterEpoch, Rules: []adminapi.RuleCounter{}}
		for _, counter := range r.Counters {
			out.Rules = append(out.Rules, adminapi.RuleCounter{ID: counter.ID, Packets: counter.Packets, Bytes: counter.Bytes})
		}
		return out, nil
	}})
	if e != nil {
		return e
	}
	health, e := startHealth(ctx, ids, service, audit)
	if e != nil {
		return e
	}
	defer health()
	server := &http.Server{Handler: admitted(handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	allowed, _ := netip.ParsePrefix(c.AllowedCIDR)
	if notifyReady() != nil {
		return ErrUnavailable
	}
	return serveAndDrain(ctx, server, func() error {
		return server.ServeTLS(&boundedListener{Listener: listener, allowed: allowed}, "", "")
	}, 5*time.Second)
}

// Serve returns as soon as Shutdown closes the listener, before active handlers
// finish. Join the drain before API's defers release their shared dependencies.
func serveAndDrain(ctx context.Context, server *http.Server, serve func() error, timeout time.Duration) error {
	serveFinished := make(chan struct{})
	shutdownFinished := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
		case <-serveFinished:
		}
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		err := server.Shutdown(stop)
		if err != nil {
			// A failed drain must cancel requests and close connections before
			// dependency cleanup, preserving the failure (including timeout).
			err = errors.Join(err, server.Close())
		}
		shutdownFinished <- err
	}()
	serveErr := serve()
	close(serveFinished)
	if err := <-shutdownFinished; err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	if errors.Is(serveErr, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return errors.Join(ErrUnavailable, serveErr)
}
