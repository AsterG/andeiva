//go:build linux

package previewruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutedNodeLinksV3StrictBindings(t *testing.T) {
	p := routedNodeLinksV3{Version: 1, Identity: strings.Repeat("a", 32), LAN: routedNodeParentV3{2, "parent-a", "02:11:22:33:44:55", 1500}, WAN: routedNodeParentV3{3, "parent-b", "02:11:22:33:44:56", 1500}}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeRoutedNodeLinksV3(data); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*routedNodeLinksV3){
		func(p *routedNodeLinksV3) { p.Identity = "" }, func(p *routedNodeLinksV3) { p.Version = 2 },
		func(p *routedNodeLinksV3) { p.WAN = p.LAN }, func(p *routedNodeLinksV3) { p.WAN.Index = p.LAN.Index },
		func(p *routedNodeLinksV3) { p.WAN.MAC = p.LAN.MAC }, func(p *routedNodeLinksV3) { p.LAN.Name = "../caller" },
		func(p *routedNodeLinksV3) { p.LAN.MTU = 0 }, func(p *routedNodeLinksV3) { p.LAN.MAC = "ff:ff:ff:ff:ff:ff" },
	} {
		q := p
		change(&q)
		raw, _ := json.Marshal(q)
		if _, err = decodeRoutedNodeLinksV3(raw); err == nil {
			t.Fatal("invalid node binding accepted")
		}
	}
	for _, raw := range []string{string(data) + " {}", strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1), strings.Replace(string(data), `"version":1`, `"version":1,"command":"caller"`, 1), strings.Repeat(" ", 4097)} {
		if _, err = decodeRoutedNodeLinksV3([]byte(raw)); err == nil {
			t.Fatal("invalid wire accepted")
		}
	}
}
