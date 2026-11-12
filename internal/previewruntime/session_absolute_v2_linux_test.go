//go:build linux

package previewruntime

import (
	"context"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

func TestAbsoluteScopedIPCV2ReceiptAndReconnect(t *testing.T){
	s,g,engine,p,next:=fixtureSessionV2(t);conn:=initializeV2(t,s,p);ctx:=context.Background();deadline:=time.Now().UTC().Add(3*time.Second)
	if e:=conn.client.ArmUntil(ctx,"absolute",p,next,deadline);e!=nil{t.Fatal(e)}
	state,e:=conn.client.State(ctx);if e!=nil||!state.Deadline.Equal(deadline){t.Fatal("receipt",e,state)}
	conn.stop();conn=dialSessionV2(t,s,nil);attachV2(t,conn.client)
	bad:=state;bad.Deadline=deadline.Add(time.Nanosecond)
	if conn.client.ApplyLease(ctx,next,bad)==nil||engine.Current()!=p.Hash{t.Fatal("changed scope applied")}
	// A rejected command closes its channel. Reconnect to the same helper lease.
	conn.stop();conn=dialSessionV2(t,s,nil);defer conn.stop();attachV2(t,conn.client)
	if e=conn.client.ApplyLease(ctx,next,state);e!=nil{t.Fatal(e)}
	if e=conn.client.ConfirmLease(ctx,state);e!=nil{t.Fatal(e)}
	if engine.Current()!=next.Hash||g.Status().Phase!="idle"||!g.Status().Deadline.Equal(deadline){t.Fatal("confirmation changed receipt")}
	var _ firewalladmin.AbsoluteLeaseAuthority=firewallipc.AuthorityV2{}
}
