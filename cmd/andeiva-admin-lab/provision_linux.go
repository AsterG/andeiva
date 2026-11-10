package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

const adminOrigin = "https://127.0.0.1:9443"
const webRoot = "/opt/andeiva-admin-lab/web"

func writeOwned(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if filepath.Clean(path) != path || validRunDirectory(filepath.Dir(path)) != nil {
		return errors.New("ANDEIVA_LAB_DIRECTORY")
	}
	base, err := os.OpenRoot("/var/tmp")
	if err != nil {
		return err
	}
	defer base.Close()
	root, err := base.OpenRoot(filepath.Base(filepath.Dir(path)))
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err = f.Chown(uid, gid); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return nil
}
func provision() (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("ANDEIVA_LAB_PROVISION_REQUIRES_ROOT")
	}
	dir, err := os.MkdirTemp("/var/tmp", "andeiva-admin-lab-")
	if err != nil {
		return "", err
	}
	if err = os.Chmod(dir, 0755); err != nil { // #nosec G302 -- Shared traversal directory; credentials and runtime state have separate owners and restrictive modes.
		return "", err
	}
	if err = os.Mkdir(filepath.Join(dir, "state"), 0700); err != nil {
		return "", err
	}
	if err = os.Chown(filepath.Join(dir, "state"), 1001, 1001); err != nil {
		return "", err
	}
	accounts := []adminauth.Account{}
	for _, user := range []struct{ name, role string }{{"admin-a", "admin"}, {"admin-b", "admin"}, {"viewer", "viewer"}} {
		var bytes [32]byte
		if _, err = rand.Read(bytes[:]); err != nil {
			return "", err
		}
		secret := hex.EncodeToString(bytes[:])
		digest := sha256.Sum256([]byte(secret))
		accounts = append(accounts, adminauth.Account{Username: user.name, Role: user.role, CredentialSHA256: hex.EncodeToString(digest[:])})
		data, _ := json.Marshal(map[string]string{"username": user.name, "credential": secret})
		if err = writeOwned(filepath.Join(dir, user.name+".json"), append(data, '\n'), 0600, 1000, 1000); err != nil {
			return "", err
		}
	}
	data, _ := json.Marshal(accounts)
	if err = writeOwned(filepath.Join(dir, "accounts.json"), append(data, '\n'), 0440, 0, 1001); err != nil {
		return "", err
	}
	if err = writeOwned(filepath.Join(dir, "auth-audit.jsonl"), nil, 0600, 1001, 1001); err != nil {
		return "", err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ANDEIVA disposable laboratory CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ANDEIVA laboratory administration"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return "", err
	}
	for _, item := range []struct {
		name, kind string
		data       []byte
		mode       os.FileMode
		uid        int
	}{{"ca.crt", "CERTIFICATE", caDER, 0644, 0}, {"server.crt", "CERTIFICATE", leafDER, 0644, 0}, {"server.key", "PRIVATE KEY", keyDER, 0400, 1001}} {
		if err = writeOwned(filepath.Join(dir, item.name), pem.EncodeToMemory(&pem.Block{Type: item.kind, Bytes: item.data}), item.mode, item.uid, 1001); err != nil {
			return "", err
		}
	}
	return dir, nil
}
func validRunDirectory(dir string) error {
	if filepath.Clean(dir) != dir || filepath.Dir(dir) != "/var/tmp" || !strings.HasPrefix(filepath.Base(dir), "andeiva-admin-lab-") || len(filepath.Base(dir)) <= len("andeiva-admin-lab-") {
		return errors.New("ANDEIVA_LAB_DIRECTORY")
	}
	root, err := os.OpenRoot("/var/tmp")
	if err != nil {
		return errors.New("ANDEIVA_LAB_DIRECTORY")
	}
	defer root.Close()
	info, err := root.Lstat(filepath.Base(dir))
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
		return errors.New("ANDEIVA_LAB_DIRECTORY")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("ANDEIVA_LAB_DIRECTORY")
	}
	return nil
}
