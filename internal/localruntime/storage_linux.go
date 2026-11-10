//go:build linux

package localruntime

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/adminclient"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/nftfixture"
	"golang.org/x/crypto/ssh"
)

func resolve(c Config) (identities, error) {
	var ids identities
	for _, v := range []struct {
		name  string
		group bool
		dst   *uint32
	}{{c.APIUser, false, &ids.APIUID}, {c.APIGroup, true, &ids.APIGID}, {c.HelperUser, false, &ids.HelperUID}, {c.HelperGroup, true, &ids.HelperGID}} {
		var value string
		if v.group {
			g, e := user.LookupGroup(v.name)
			if e != nil {
				return ids, ErrUnavailable
			}
			value = g.Gid
		} else {
			u, e := user.Lookup(v.name)
			if e != nil {
				return ids, ErrUnavailable
			}
			value = u.Uid
		}
		n, e := parseID(value)
		if e != nil {
			return ids, e
		}
		*v.dst = n
	}
	if !ids.valid() {
		return ids, ErrUnavailable
	}
	if safeAccount(c.APIUser, ids.APIGID) != nil || safeAccount(c.HelperUser, ids.HelperGID) != nil {
		return ids, ErrUnavailable
	}
	return ids, nil
}

func safeAccount(name string, gid uint32) error {
	u, e := user.Lookup(name)
	if e != nil || u.Gid != strconv.FormatUint(uint64(gid), 10) {
		return ErrUnavailable
	}
	groups, e := u.GroupIds()
	if e != nil || len(groups) != 1 || groups[0] != u.Gid {
		return ErrUnavailable
	}
	f, e := os.Open("/etc/passwd")
	if e != nil {
		return ErrUnavailable
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return ErrUnavailable
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == name {
			if fields[6] == "/usr/sbin/nologin" || fields[6] == "/sbin/nologin" || fields[6] == "/bin/false" {
				return nil
			}
			return ErrUnavailable
		}
	}
	return ErrUnavailable
}

func directory(path string, uid, gid uint32, mode os.FileMode) error {
	i, e := os.Lstat(path)
	if e != nil || !i.IsDir() || i.Mode().Perm() != mode {
		return ErrUnavailable
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uid || s.Gid != gid {
		return ErrUnavailable
	}
	return nil
}

func readFile(dir, name string, uid, gid uint32, mode os.FileMode, limit int64) ([]byte, error) {
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer r.Close()
	f, e := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != mode || i.Size() > limit {
		return nil, ErrUnavailable
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uid || s.Gid != gid || s.Nlink != 1 {
		return nil, ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrUnavailable
	}
	return b, nil
}

func writeNew(root *os.Root, name string, b []byte, uid, gid uint32, mode os.FileMode) error {
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if e != nil {
		return ErrUnavailable
	}
	defer f.Close()
	if uid > 2147483647 || gid > 2147483647 {
		return ErrUnavailable
	}
	if f.Chown(int(uid), int(gid)) != nil || f.Chmod(mode) != nil {
		return ErrUnavailable
	}
	if _, e = f.Write(b); e != nil || f.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func syncDir(path string) error {
	r, e := os.OpenRoot(path)
	if e != nil {
		return ErrUnavailable
	}
	defer r.Close()
	f, e := r.Open(".")
	if e != nil {
		return ErrUnavailable
	}
	defer f.Close()
	return f.Sync()
}
func encode(v any) []byte { b, _ := json.Marshal(v); return append(b, '\n') }
func randomID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(b[:]), nil
}

func certificates(c Config) (ca, cert, key, host, public []byte, err error) {
	caPub, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	now := time.Now()
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	issuer := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ANDEIVA local laboratory CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, issuer, issuer, caPub, caKey)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	serial, e = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	leaf := &x509.Certificate{SerialNumber: serial, NotBefore: issuer.NotBefore, NotAfter: issuer.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(c.LANAddress), net.ParseIP("127.0.0.1")}}
	for _, iface := range nftfixture.LocalInventory() {
		for _, address := range iface.Addresses {
			leaf.IPAddresses = append(leaf.IPAddresses, net.ParseIP(address))
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, leaf, issuer, pub, caKey)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	hostPub, hostKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	hostDER, e := x509.MarshalPKCS8PrivateKey(hostKey)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	sshPub, e := ssh.NewPublicKey(hostPub)
	if e != nil {
		return nil, nil, nil, nil, nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: hostDER}), ssh.MarshalAuthorizedKey(sshPub), nil
}

// provision creates no OS accounts and never overwrites credentials or a journal.
func provision(dir string, c Config) error {
	if os.Geteuid() != 0 || !validDirectory(dir) || c.Validate() != nil {
		return ErrUnavailable
	}
	ids, e := resolve(c)
	if e != nil {
		return e
	}
	if _, e = os.Lstat(dir); e == nil {
		old, _, err := load(dir)
		if err != nil || old != c {
			return ErrUnavailable
		}
		_, e = readFile(dir, "server.key", 0, ids.APIGID, 0440, 8192)
		return e
	} else if !os.IsNotExist(e) {
		return ErrUnavailable
	}
	// Root-owned traversal for the API group only; helper has no access to secrets.
	if os.Mkdir(dir, 0750) != nil || os.Chown(dir, 0, int(ids.APIGID)) != nil || os.Chmod(dir, 0750) != nil { // #nosec G302 -- Root-owned parent grants traversal only to the distinct API group; secrets are 0440 and state/operator children are 0700.
		return ErrUnavailable
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer r.Close()
	for _, d := range []struct {
		name     string
		uid, gid uint32
	}{{"state", ids.APIUID, ids.APIGID}, {"audit", ids.APIUID, ids.APIGID}, {"runtime", ids.APIUID, ids.APIGID}, {"operator", 0, 0}} {
		if r.Mkdir(d.name, 0700) != nil || r.Chown(d.name, int(d.uid), int(d.gid)) != nil || r.Chmod(d.name, 0700) != nil {
			return ErrUnavailable
		}
	}
	accounts := []adminauth.Account{}
	for _, u := range []struct{ name, role string }{{"admin-a", "admin"}, {"admin-b", "admin"}, {"viewer", "viewer"}} {
		var secret [32]byte
		if _, e := rand.Read(secret[:]); e != nil {
			return e
		}
		credential := hex.EncodeToString(secret[:])
		hash := sha256.Sum256([]byte(credential))
		accounts = append(accounts, adminauth.Account{Username: u.name, Role: u.role, CredentialSHA256: hex.EncodeToString(hash[:])})
		if e = writeNew(r, "operator/"+u.name+".json", encode(adminclient.Credentials{Username: u.name, Credential: credential}), 0, 0, 0600); e != nil {
			return e
		}
	}
	ca, cert, key, host, pub, e := certificates(c)
	if e != nil {
		return e
	}
	for _, f := range []struct {
		name string
		b    []byte
	}{{"ca.crt", ca}, {"server.crt", cert}, {"server.key", key}, {"host.key", host}, {"host.pub", pub}, {"accounts.json", encode(accounts)}, {"config.json", encode(c)}, {"identities.json", encode(ids)}} {
		if e = writeNew(r, f.name, f.b, 0, ids.APIGID, 0440); e != nil {
			return e
		}
	}
	for _, d := range []string{"operator", "state", "audit", "runtime", ""} {
		if syncDir(filepath.Join(dir, d)) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

func load(dir string) (Config, identities, error) {
	var c Config
	var ids identities
	if !validDirectory(dir) {
		return c, ids, ErrUnavailable
	}
	i, e := os.Lstat(dir)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0750 {
		return c, ids, ErrUnavailable
	}
	stat, ok := i.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return c, ids, ErrUnavailable
	}
	b, e := readFile(dir, "config.json", 0, stat.Gid, 0440, 4096)
	if e != nil || firewallipc.Decode(b, &c) != nil || c.Validate() != nil {
		return c, ids, ErrUnavailable
	}
	b, e = readFile(dir, "identities.json", 0, stat.Gid, 0440, 4096)
	if e != nil || firewallipc.Decode(b, &ids) != nil || !ids.valid() || stat.Gid != ids.APIGID {
		return c, ids, ErrUnavailable
	}
	current, e := resolve(c)
	if e != nil || current != ids {
		return c, ids, ErrUnavailable
	}
	for _, name := range []string{"state", "audit", "runtime"} {
		if directory(filepath.Join(dir, name), ids.APIUID, ids.APIGID, 0700) != nil {
			return c, ids, ErrUnavailable
		}
	}
	return c, ids, nil
}

const auditBudget = 8 << 20

type auditLog struct {
	mu     sync.Mutex
	file   *os.File
	size   int64
	failed bool
}

func openAudit(dir string, ids identities) (*auditLog, error) {
	path := filepath.Join(dir, "audit")
	if directory(path, ids.APIUID, ids.APIGID, 0700) != nil {
		return nil, ErrUnavailable
	}
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	f, e := r.OpenFile("auth.jsonl", os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	fail := func() (*auditLog, error) { _ = f.Close(); return nil, ErrUnavailable }
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || i.Size() >= auditBudget {
		return fail()
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != ids.APIUID || st.Gid != ids.APIGID || st.Nlink != 1 {
		return fail()
	}
	b, e := io.ReadAll(io.LimitReader(f, auditBudget+1))
	if e != nil || len(b) > auditBudget || (len(b) > 0 && b[len(b)-1] != '\n') {
		return fail()
	}
	scan := bufio.NewScanner(bytes.NewReader(b))
	scan.Buffer(make([]byte, 4096), 4096)
	for scan.Scan() {
		var event adminauth.Event
		if firewallipc.Decode(scan.Bytes(), &event) != nil || event.At.IsZero() {
			return fail()
		}
	}
	if scan.Err() != nil || syncDir(path) != nil {
		return fail()
	}
	return &auditLog{file: f, size: i.Size()}, nil
}
func (a *auditLog) Append(event adminauth.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b := encode(event)
	if a.failed || len(b) > 4096 || a.size+int64(len(b)) > auditBudget {
		a.failed = true
		return ErrUnavailable
	}
	n, e := a.file.Write(b)
	a.size += int64(n)
	if e != nil || n != len(b) || a.file.Sync() != nil {
		a.failed = true
		return ErrUnavailable
	}
	return nil
}
func (a *auditLog) Close() error { a.mu.Lock(); defer a.mu.Unlock(); return a.file.Close() }
func (a *auditLog) healthy() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.failed && a.size < auditBudget
}

func bootRequired(dir string, ids identities, boot string) (bool, error) {
	if !bootPattern.MatchString(boot) {
		return false, ErrUnavailable
	}
	b, e := readFile(filepath.Join(dir, "runtime"), "boot-id", ids.APIUID, ids.APIGID, 0600, 64)
	if e != nil {
		_, stat := os.Lstat(filepath.Join(dir, "runtime", "boot-id"))
		if os.IsNotExist(stat) {
			entries, err := os.ReadDir(filepath.Join(dir, "state"))
			if err == nil && len(entries) == 0 {
				return true, nil
			}
		}
		return false, e
	}
	if !bootPattern.Match(b) {
		return false, ErrUnavailable
	}
	return string(b) != boot, nil
}
func markBoot(dir string, ids identities, boot string) error {
	if !bootPattern.MatchString(boot) {
		return ErrUnavailable
	}
	path := filepath.Join(dir, "runtime")
	r, e := os.OpenRoot(path)
	if e != nil {
		return e
	}
	defer r.Close()
	id, e := randomID()
	if e != nil {
		return e
	}
	tmp := "boot-" + id
	if e = writeNew(r, tmp, []byte(boot), ids.APIUID, ids.APIGID, 0600); e != nil {
		return e
	}
	if e = r.Rename(tmp, "boot-id"); e != nil {
		return e
	}
	return syncDir(path)
}
