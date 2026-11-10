//go:build linux

package previewruntime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

func certificates(address string, now time.Time) ([]byte, []byte, []byte, error) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, nil, e
	}
	serverKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, nil, e
	}
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			return nil
		}
		return n
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "ANDEIVA preview trust anchor"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "ANDEIVA preview management"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(address)}}
	if ca.SerialNumber == nil || leaf.SerialNumber == nil || leaf.IPAddresses[0] == nil {
		return nil, nil, nil, ErrConfiguration
	}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return nil, nil, nil, e
	}
	certDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if e != nil {
		return nil, nil, nil, e
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(serverKey)
	if e != nil {
		return nil, nil, nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// Provision is explicit, root-only and never overwrites an existing installation.
// Partial initialization is preserved and rejected; it is not silently repaired.
func Provision(c Config) error {
	if os.Geteuid() != 0 || c.Validate() != nil {
		return ErrIdentity
	}
	ids, e := resolve(c)
	if e != nil {
		return e
	}
	if _, e = os.Lstat(DataDir); e == nil {
		old, e := LoadIdentities(c)
		if e != nil || old != ids {
			return ErrStorage
		}
		_, e = loadTLS(c, ids)
		if e != nil {
			return e
		}
		_, e = loadAccounts(ids)
		if e != nil {
			return e
		}
		return provisionSocket(c)
	} else if !os.IsNotExist(e) {
		return ErrStorage
	}
	if safeParents(DataDir) != nil {
		return ErrStorage
	}
	if os.Mkdir(DataDir, 0755) != nil { // #nosec G301 -- Root-owned traversal boundary shared by separate service identities; secret children enforce 0700/0440/0600.
		return ErrStorage
	}
	if os.Chmod(DataDir, 0755) != nil { // #nosec G302 -- Newly created root-owned parent must be traversable by API and helper; child files enforce access control.
		return ErrStorage
	}
	root, e := os.OpenRoot(DataDir)
	if e != nil {
		return ErrStorage
	}
	defer root.Close()
	for _, d := range []struct {
		name     string
		uid, gid uint32
		mode     os.FileMode
	}{{"state", ids.APIUID, ids.APIGID, 0700}, {"audit", ids.APIUID, ids.APIGID, 0700}, {"local", ids.APIUID, ids.APIGID, 0700}, {"operator", 0, 0, 0700}} {
		if root.Mkdir(d.name, d.mode) != nil || root.Chown(d.name, int(d.uid), int(d.gid)) != nil || root.Chmod(d.name, d.mode) != nil {
			return ErrStorage
		}
	}
	accounts := []adminauth.Account{}
	for _, u := range []struct{ name, role string }{{"admin-a", "admin"}, {"admin-b", "admin"}, {"viewer", "viewer"}} {
		var secret [32]byte
		if _, e = rand.Read(secret[:]); e != nil {
			return ErrStorage
		}
		credential := hex.EncodeToString(secret[:])
		digest := sha256.Sum256([]byte(credential))
		accounts = append(accounts, adminauth.Account{Username: u.name, Role: u.role, CredentialSHA256: hex.EncodeToString(digest[:])})
		if e = writeNew(root, "operator/"+u.name+".json", marshal(map[string]string{"username": u.name, "credential": credential}), 0600, 0, 0); e != nil {
			return e
		}
	}
	addr, _ := netip.ParseAddrPort(c.ListenAddress)
	ca, cert, key, e := certificates(addr.Addr().String(), time.Now())
	if e != nil {
		return ErrStorage
	}
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
		gid  uint32
	}{{"ca.crt", ca, 0644, 0}, {"server.crt", cert, 0440, ids.APIGID}, {"server.key", key, 0440, ids.APIGID}, {"accounts.json", marshal(accounts), 0440, ids.APIGID}} {
		if e = writeNew(root, f.name, f.data, f.mode, 0, f.gid); e != nil {
			return e
		}
	}
	for _, d := range []string{"state", "audit", "local", "operator"} {
		if syncDirectory(filepath.Join(DataDir, d)) != nil {
			return ErrStorage
		}
	}
	if e = provisionSocket(c); e != nil {
		return e
	}
	if e = writeNew(root, "identities.json", marshal(ids), 0644, 0, 0); e != nil {
		return e
	}
	return syncDirectory(DataDir)
}
func loadAccounts(ids Identities) ([]adminauth.Account, error) {
	b, e := readOwned(DataDir+"/accounts.json", 0, ids.APIGID, 0440, 16384)
	if e != nil {
		return nil, e
	}
	var a []adminauth.Account
	if firewallipc.Decode(b, &a) != nil {
		return nil, ErrConfiguration
	}
	return a, nil
}
func loadTLS(c Config, ids Identities) (tls.Certificate, error) {
	cert, e := readOwned(DataDir+"/server.crt", 0, ids.APIGID, 0440, 16384)
	if e != nil {
		return tls.Certificate{}, e
	}
	key, e := readOwned(DataDir+"/server.key", 0, ids.APIGID, 0440, 16384)
	if e != nil {
		return tls.Certificate{}, e
	}
	ca, e := readOwned(DataDir+"/ca.crt", 0, 0, 0644, 16384)
	if e != nil {
		return tls.Certificate{}, e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return pair, ErrConfiguration
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return pair, ErrConfiguration
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return pair, ErrConfiguration
	}
	addr, _ := netip.ParseAddrPort(c.ListenAddress)
	if _, e = leaf.Verify(x509.VerifyOptions{DNSName: addr.Addr().String(), Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return pair, ErrConfiguration
	}
	return pair, nil
}
