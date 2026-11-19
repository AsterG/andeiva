//go:build linux && andeiva_native_dhcp_diagnostics

package previewruntime

import "sync"

// Only the native fixture installs a consumer. Registration occurs after root
// validates the producer bootstrap, before activation can emit or lose events.
var nativeDHCPDiagnosticRegistryV4 struct {
	sync.Mutex
	consumer func(*RoutedDHCPOwnerV3)
}

func registerNativeDHCPDiagnosticV4(owner *RoutedDHCPOwnerV3) {
	nativeDHCPDiagnosticRegistryV4.Lock()
	defer nativeDHCPDiagnosticRegistryV4.Unlock()
	if nativeDHCPDiagnosticRegistryV4.consumer != nil {
		nativeDHCPDiagnosticRegistryV4.consumer(owner)
	}
}

func captureNativeDHCPDiagnosticV4(consumer func(*RoutedDHCPOwnerV3)) (func(), error) {
	r := &nativeDHCPDiagnosticRegistryV4
	r.Lock()
	defer r.Unlock()
	if consumer == nil || r.consumer != nil {
		return nil, ErrIdentity
	}
	r.consumer = consumer
	var once sync.Once
	return func() { once.Do(func() { r.Lock(); defer r.Unlock(); r.consumer = nil }) }, nil
}
