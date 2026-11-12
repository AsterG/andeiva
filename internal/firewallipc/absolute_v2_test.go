package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestAbsoluteCodecStrictDeadlineAndMixedVersion(t *testing.T){
	p,_:=configpoc.Canonical(configpoc.Config{SchemaVersion:1,DefaultAction:"deny"});deadline:=time.Date(2026,11,12,1,2,3,123456789,time.UTC)
	m:=requestFixtureV2("arm_until",ArmUntilPayloadV2{"exact",p,p,deadline});raw,_:=json.Marshal(m)
	if _,_,e:=DecodeRequestV2(raw);e!=nil{t.Fatal(e)}
	for name,bad:=range map[string]string{
		"ttl":strings.Replace(string(raw),`"id":"exact"`,`"id":"exact","ttl_ns":1000000000`,1),
		"alias":strings.Replace(string(raw),`"deadline":`,`"Deadline":`,1),
		"duplicate":strings.Replace(string(raw),`"id":"exact"`,`"id":"exact","id":"other"`,1),
		"offset":strings.Replace(string(raw),".123456789Z",".123456789+00:00",1),
		"zero":strings.Replace(string(raw),"2026-11-12T01:02:03.123456789Z","0001-01-01T00:00:00Z",1),
	}{t.Run(name,func(t *testing.T){if _,_,e:=DecodeRequestV2([]byte(bad));e==nil{t.Fatal("invalid accepted")}})}
	// The v1 decoder rejects the additive operation; there is no TTL downgrade.
	var legacy Message
	if e:=Decode(raw,&legacy);e==nil{t.Fatal("v1 accepted absolute frame")}
	for _,verb:=range []string{"apply_scoped","confirm_scoped"}{
		scope:=RecoveryScope{"exact",p.Hash,p.Hash,deadline};var payload any=scope;if verb=="apply_scoped"{payload=ApplyScopedPayloadV2{p,scope}}
		m=requestFixtureV2(verb,payload);raw,_=json.Marshal(m);if _,_,e:=DecodeRequestV2(raw);e!=nil{t.Fatal(verb,e)}
	}
}
