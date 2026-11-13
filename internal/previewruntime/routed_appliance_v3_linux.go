//go:build linux

package previewruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"golang.org/x/sys/unix"
)

type routedApplianceCloserV3 func() error

func (c routedApplianceCloserV3) Close() error { return c() }

// RunRoutedApplianceRoleV3 accepts only fixed root-launched roles. Deployment
// configuration has one root-owned path; no child argument selects a path,
// identity, namespace, store or executable.
func RunRoutedApplianceRoleV3(ctx context.Context, role string) error {
	if ctx == nil || ctx.Err() != nil || (role != RoutedHelperRoleV3 && role != RoutedAPIRoleV3) {
		return ErrConfiguration
	}
	c, err := LoadConfig(ConfigPath)
	if err != nil {
		return err
	}
	factories, err := NewRoutedApplianceFactoriesV3(c)
	if err != nil {
		return err
	}
	return RunRoutedLaunchRoleV3(ctx, role, factories)
}

// The grouped coordinator owns both domains. This deliberately unavailable
// engine is never an alternative writer or fabricated local readback.
type routedApplianceLocalV3 struct{}

func (routedApplianceLocalV3) Name() string                                    { return "grouped-local-unavailable" }
func (routedApplianceLocalV3) Validate(configpoc.Config) error                 { return ErrUnavailable }
func (routedApplianceLocalV3) Apply(context.Context, configpoc.Revision) error { return ErrUnavailable }
func (routedApplianceLocalV3) Current() string                                 { return "" }

// NewRoutedApplianceFactoriesV3 connects fixed launcher roles to real appliance
// resources. It does not migrate a store, create namespaces, bind a listener,
// or activate an installed unit. The authenticated launcher supplies all FDs.
func NewRoutedApplianceFactoriesV3(c Config) (RoutedLaunchFactoriesV3, error) {
	if c.Validate() != nil {
		return RoutedLaunchFactoriesV3{}, ErrConfiguration
	}
	var pair tls.Certificate
	var assets *os.Root
	var management *os.File
	var identity Identities
	var auditLog *auditLog
	return RoutedLaunchFactoriesV3{
		Helper: openRoutedApplianceHelperV3,
		API: func(ctx context.Context, launch RoutedLaunchContextV3) (out OperationsRuntimeOptionsV2, cleanup io.Closer, result error) {
			if ctx == nil || ctx.Err() != nil || !launch.Integrity || launch.IntegrityRoot != nil || launch.StoreBudget.Bytes == 0 || launch.StoreBudget.Inodes == 0 || validateRoutedManagementV3(launch.Management, c) != nil {
				return out, nil, ErrIdentity
			}
			actual, err := LoadIdentities(c)
			if err != nil || actual != launch.Identities {
				return out, nil, ErrIdentity
			}
			management, identity = launch.Management, actual
			pair, err = loadTLS(c, actual)
			if err != nil {
				return out, nil, err
			}
			accounts, err := loadAccounts(actual)
			if err != nil {
				return out, nil, err
			}
			audit, err := openAudit(DataDir+"/audit", actual.APIUID, actual.APIGID)
			if err != nil {
				return out, nil, err
			}
			auditLog = audit
			var pools [3]*recoveryreserve.PoolV2
			cleanup = routedApplianceCloserV3(func() error {
				result := audit.Close()
				for _, p := range pools {
					if p != nil {
						result = errors.Join(result, p.Close())
					}
				}
				if assets != nil {
					result = errors.Join(result, assets.Close())
				}
				return result
			})
			auth, err := adminauth.New(accounts, audit.Append)
			if err != nil {
				return out, cleanup, err
			}
			for i, resource := range []RoutedReaderRootV3{launch.Admission, launch.Plan, launch.Emergency} {
				pools[i], err = recoveryreserve.OpenSharedV2(resource.Root, resource.Access)
				if err != nil {
					return out, cleanup, err
				}
				profile, e := pools[i].Profile()
				if e != nil || profile != resource.Profile {
					return out, cleanup, ErrIdentity
				}
			}
			if safeParents(WebRoot+"/index.html") != nil {
				return out, cleanup, ErrStorage
			}
			assets, err = os.OpenRoot(WebRoot)
			if err != nil {
				return out, cleanup, ErrStorage
			}
			if _, err = fs.Stat(assets.FS(), "index.html"); err != nil {
				return out, cleanup, ErrStorage
			}
			out = OperationsRuntimeOptionsV2{Store: launch.Store, Budget: launch.StoreBudget, Auth: auth, Origin: c.Origin(), Static: routedApplianceStaticV3(assets.FS()), Local: []configpoc.Engine{routedApplianceLocalV3{}}, Runtime: configpoc.RuntimeOptionsV2{SharedReader: &launch.Access, Pools: configpoc.RuntimePoolsV2{Admission: pools[0], Plan: pools[1], Emergency: pools[2]}, BootID: launch.Metadata.BootID, GuardDeadlines: true}}
			return out, cleanup, nil
		},
		ServeAPI: func(ctx context.Context, r *RoutedOperationsRuntimeV3, ready func() error) error {
			if r == nil || r.Service == nil || r.routed == nil || management == nil || auditLog == nil || len(pair.Certificate) == 0 {
				return ErrIdentity
			}
			// The descriptor is retained only by this API role; the root factory
			// does not grant NET_ADMIN/NET_RAW to bind management on its own.
			observed, err := r.routed.Call(ctx, "observe", struct{}{})
			if err != nil || observed.Observed.Revision == "" {
				return ErrUnavailable
			}
			stop, err := startHealth(ctx, identity, routedApplianceHealthV3{runtime: r}, auditLog)
			if err != nil {
				return err
			}
			defer stop()
			return serveRoutedManagementV3(ctx, c, management, pair, r.Handler, ready)
		},
	}, nil
}

func openRoutedApplianceHelperV3(ctx context.Context, c RoutedLaunchContextV3) (out RoutedHelperComponentsV3, result error) {
	if ctx == nil || ctx.Err() != nil || !c.Integrity || c.IntegrityRoot == nil || c.Management != nil {
		return out, ErrIdentity
	}
	identity := networkexecutor.OwnedNamespaceIdentity{UID: c.Identities.HelperUID, GID: c.Identities.IPCGID, Namespace: c.Metadata.GatewayNamespace, Host: c.Metadata.HostNamespace, BootID: c.Metadata.BootID, RunID: c.Metadata.RunID}
	var pools [3]*recoveryreserve.ReadOnlyPoolV2
	defer func() {
		for _, p := range pools {
			if p != nil {
				result = errors.Join(result, p.Close())
			}
		}
	}()
	for i, resource := range []RoutedReaderRootV3{c.Admission, c.Plan, c.Emergency} {
		p, err := recoveryreserve.OpenReadOnlyV2(resource.Root, resource.Access, resource.Profile)
		if err != nil {
			return out, err
		}
		pools[i] = p
	}
	reader, err := configpoc.NewRoutedSelectionReaderV2(c.Store, configpoc.SelectionReaderOptionsV2{Access: c.Access, Identity: identity, Admission: pools[0], Plan: pools[1], Emergency: pools[2], Budget: c.Budget})
	if err != nil {
		return out, err
	}
	view, err := reader.PrepareCurrentView(ctx)
	if err != nil {
		return out, err
	}
	kernel, err := newRoutedKernelV3(c.Metadata)
	if err != nil {
		return out, err
	}
	network, err := networkexecutor.NewInOwnedNamespaceWithReader(ctx, c.Gateway, c.Host, identity, c.Access.ReaderGID)
	if err != nil {
		return out, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, network.Close())
		}
	}()
	listeners, err := newRoutedEmptyListenersV3(c.Metadata)
	if err != nil {
		return out, err
	}
	bindings, err := routedApplianceBindingsV3()
	if err != nil {
		return out, err
	}
	authority, err := NewRoutedAuthority(kernel, network, listeners, routedactivation.Options{Legacy: view.Saved.Firewall, Local: &view.Saved.LocalServices, ObservedBindings: bindings}, identity)
	if err != nil {
		return out, err
	}
	out.Cleanup = routedApplianceCloserV3(func() error { return errors.Join(authority.group.Close(), network.Close()) })
	out.Authority = authority
	out.Compatibility, err = NewRoutedReadbackSessionV3(c.Metadata.RunID, c.Metadata.GatewayNamespace, authority)
	if err != nil {
		return out, err
	}
	return out, nil
}

func routedApplianceBindingsV3() ([]networkplan.Binding, error) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) > 3 {
		return nil, ErrIdentity
	}
	return routedApplianceBindingsFromV3(interfaces)
}
func routedApplianceBindingsFromV3(interfaces []net.Interface) ([]networkplan.Binding, error) {
	if len(interfaces) > 3 {
		return nil, ErrIdentity
	}
	var bindings []networkplan.Binding
	seenName, seenMAC := map[string]bool{}, map[string]bool{}
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback != 0 {
			continue
		}
		if item.Flags&net.FlagUp == 0 || len(item.HardwareAddr) != 6 || !device.MatchString(item.Name) {
			return nil, ErrIdentity
		}
		mac := item.HardwareAddr.String()
		if seenName[item.Name] || seenMAC[mac] {
			return nil, ErrIdentity
		}
		seenName[item.Name], seenMAC[mac] = true, true
		bindings = append(bindings, networkplan.Binding{Name: item.Name, HardwareAddress: mac})
	}
	if len(bindings) != 2 {
		return nil, ErrIdentity
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Name < bindings[j].Name })
	return bindings, nil
}

func validateRoutedManagementV3(file *os.File, c Config) error {
	if file == nil || c.Validate() != nil || validateListener(int(file.Fd()), c) != nil {
		return ErrIdentity
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return ErrIdentity
	}
	defer unix.Close(fd)
	want, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return ErrIdentity
	}
	actual, err := unix.GetsockoptUint64(int(file.Fd()), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil || actual != want {
		return ErrIdentity
	}
	return nil
}

func serveRoutedManagementV3(ctx context.Context, c Config, file *os.File, pair tls.Certificate, handler http.Handler, ready func() error) error {
	if ctx == nil || ctx.Err() != nil || validateRoutedManagementV3(file, c) != nil || len(pair.Certificate) == 0 || handler == nil || ready == nil {
		return ErrIdentity
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return ErrIdentity
	}
	defer listener.Close()
	server := &http.Server{Handler: admitted(handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	allowed, _ := netip.ParsePrefix(c.AllowedCIDR)
	if err := ready(); err != nil {
		return err
	}
	return serveAndDrain(ctx, server, func() error { return server.ServeTLS(&boundedListener{Listener: listener, allowed: allowed}, "", "") }, 5*time.Second)
}

// Health is deliberately stricter than management socket availability. A
// pending/reconciling service may accept its authorized closing operation but
// cannot report itself as integrity-qualified.
type routedApplianceHealthV3 struct{ runtime *RoutedOperationsRuntimeV3 }

func (h routedApplianceHealthV3) Observed(ctx context.Context, _ configpoc.Principal) (firewalladmin.Observation, error) {
	if h.runtime == nil || h.runtime.Service == nil || h.runtime.routed == nil {
		return firewalladmin.Observation{}, ErrUnavailable
	}
	value, err := h.runtime.routed.Call(ctx, "observe", struct{}{})
	if err != nil {
		return firewalladmin.Observation{}, err
	}
	receipt := value.Observed.Receipt
	qualified := h.runtime.Service.RuntimeReadbackReadyV1(value.Observed.Revision) && (receipt.Phase == "idle" || receipt.Phase == "bootstrap") && value.Observed.Revision != ""
	return firewalladmin.Observation{Hash: value.Observed.Revision, Phase: receipt.Phase, RecoveryRequired: !qualified}, nil
}

func routedApplianceStaticV3(assets fs.FS) http.Handler {
	files := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/firewall" || r.URL.Path == "/firewall/" {
			copy := r.Clone(r.Context())
			url := *r.URL
			copy.URL = &url
			copy.URL.Path = "/"
			files.ServeHTTP(w, copy)
			return
		}
		files.ServeHTTP(w, r)
	})
}
