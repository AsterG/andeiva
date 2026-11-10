package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
)

func artifactDigest(c configpoc.Config) (string, error) {
	a, err := firewallnft.Compile(c)
	return a.Digest, err
}
func apiProcess(dir, run, namespace, epoch, boot, parent string) error {
	if os.Geteuid() != 1001 || validRunDirectory(dir) != nil {
		return errors.New("ANDEIVA_ADMIN_PROCESS_IDENTITY")
	}
	if err := checkPrivileges(false); err != nil {
		return err
	}
	if err := bindParent(parent); err != nil {
		return err
	}
	ns, err := strconv.ParseUint(namespace, 10, 64)
	if err != nil || ns == 0 {
		return firewallipc.ErrChannel
	}
	base, err := strconv.ParseUint(epoch, 10, 32)
	if err != nil || base == 0 {
		return firewallipc.ErrChannel
	}
	if boot != "true" && boot != "false" {
		return firewallipc.ErrChannel
	}
	input, output := os.NewFile(4, "helper-response"), os.NewFile(3, "helper-request")
	if input == nil || output == nil {
		return firewallipc.ErrChannel
	}
	client, err := firewallipc.New(input, output, run, base<<32, ns, artifactDigest)
	if err != nil {
		return err
	}
	defer client.Close()
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat("accounts.json")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0440 {
		return errors.New("ANDEIVA_ADMIN_ACCOUNT_FILE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 1001 {
		return errors.New("ANDEIVA_ADMIN_ACCOUNT_FILE")
	}
	data, err := root.ReadFile("accounts.json")
	if err != nil || len(data) > 16384 {
		return errors.New("ANDEIVA_ADMIN_ACCOUNT_FILE")
	}
	var accounts []adminauth.Account
	if err = firewallipc.Decode(data, &accounts); err != nil {
		return err
	}
	audit, err := root.OpenFile("auth-audit.jsonl", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer audit.Close()
	info, err = audit.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("ANDEIVA_ADMIN_AUDIT_FILE")
	}
	auditBytes := info.Size()
	var auditMu sync.Mutex
	auth, err := adminauth.New(accounts, func(event adminauth.Event) error {
		auditMu.Lock()
		defer auditMu.Unlock()
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if int64(len(data))+auditBytes > 1<<20 {
			return adminauth.ErrUnavailable
		}
		n, err := audit.Write(data)
		auditBytes += int64(n)
		if err != nil {
			return err
		}
		return audit.Sync()
	})
	if err != nil {
		return err
	}
	initial := configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	core, err := configpoc.Open(filepath.Join(dir, "state"), []configpoc.Engine{client}, configpoc.Options{Initial: &initial, Boot: boot == "true"})
	if err != nil {
		return err
	}
	if err = client.Recovered(context.Background()); err != nil {
		_ = core.Close()
		return err
	}
	service, err := firewalladmin.New(core, firewallipc.Authority{Client: client})
	if err != nil {
		_ = core.Close()
		return err
	}
	defer service.Close()
	assets, err := os.OpenRoot(webRoot)
	if err != nil {
		return err
	}
	defer assets.Close()
	if _, err = fs.Stat(assets.FS(), "index.html"); err != nil {
		return err
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
	handler, err := adminapi.New(adminapi.Options{Origin: adminOrigin, Auth: auth, Backend: service, Static: static, Observe: func(ctx context.Context) (adminapi.Effective, error) {
		r, err := client.Observe(ctx)
		if err != nil {
			return adminapi.Effective{}, err
		}
		out := adminapi.Effective{Revision: r.Hash, Rules: []adminapi.RuleCounter{}}
		for _, counter := range r.Counters {
			out.Rules = append(out.Rules, adminapi.RuleCounter{ID: counter.ID, Packets: counter.Packets, Bytes: counter.Bytes})
		}
		return out, nil
	}})
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:9443")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: admitted(handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	fmt.Println("ANDEIVA_ADMIN_READY")
	return server.ServeTLS(&boundedListener{Listener: listener}, "", "")
}
