package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type routedCompensationSourceV3 interface {
	resolveCompensationV3(context.Context, firewallipc.RoutedCompensationV3) (configpoc.RoutedCompensationAuthorizationV1, error)
	resolveConsumedCompensationV3(context.Context, configpoc.RoutedCompensationAuthorizationV1, configpoc.SelectionReferenceV2) (configpoc.RoutedCompensationAuthorizationV1, error)
}

// Only trusted assembly can supply a consumer. In particular the original
// Recover method cannot substitute for a consumer of durable compensation.
type routedCompensationConsumerV3 interface {
	recoverCompensationV3(context.Context, configpoc.RoutedCompensationAuthorizationV1) error
}

// Owned by one authenticated connection. The next request invalidates this
// slot even when denied, and closing the connection discards it.
type routedCompensationHandoffV3 struct {
	request       firewallipc.RoutedCompensationV3
	authorization configpoc.RoutedCompensationAuthorizationV1
	expires       time.Time
}

func (h routedCompensationHandoffV3) matches(p firewallipc.RoutedCompensationV3, now time.Time) bool {
	return h.request.Ticket != "" && h.request.Ticket == p.Ticket &&
		h.request.Reference == p.Reference && h.request.Operation == p.Operation && now.Before(h.expires)
}

func (s *RoutedSessionV3) dispatchSessionV3(ctx context.Context, c firewallipc.RoutedCommandV3, handoff *routedCompensationHandoffV3) (any, error) {
	previous := *handoff
	*handoff = routedCompensationHandoffV3{}
	if c.Compensation == nil {
		return s.dispatch(ctx, c)
	}
	source, read := s.source.(routedCompensationSourceV3)
	consumer, recover := s.authority.(routedCompensationConsumerV3)
	if !read || !recover || !freshScopeAllowedV3(s.integrity) || ctx.Err() != nil {
		return nil, configpoc.ErrRecovery
	}
	p := *c.Compensation
	switch c.Verb {
	case "prepare_recover":
		expires, ok := ctx.Deadline()
		if !ok {
			return nil, configpoc.ErrRecovery
		}
		auth, err := source.resolveCompensationV3(ctx, p)
		if err != nil {
			return nil, err
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, configpoc.ErrRecovery
		}
		if !freshScopeAllowedV3(s.integrity) || ctx.Err() != nil || !time.Now().Before(expires) {
			return nil, configpoc.ErrRecovery
		}
		p.Ticket = hex.EncodeToString(nonce[:])
		*handoff = routedCompensationHandoffV3{request: p, authorization: auth, expires: expires}
		return firewallipc.RoutedCompensationPreparedV3{Ticket: p.Ticket}, nil
	case "recover":
		if !previous.matches(p, time.Now()) {
			return nil, configpoc.ErrRecovery
		}
		read, cancel := context.WithDeadline(ctx, previous.expires)
		defer cancel()
		auth, err := source.resolveConsumedCompensationV3(read, previous.authorization, p.Selection)
		if err != nil {
			return nil, err
		}
		if !freshScopeAllowedV3(s.integrity) || read.Err() != nil || !time.Now().Before(previous.expires) {
			return nil, configpoc.ErrRecovery
		}
		return struct{}{}, consumer.recoverCompensationV3(ctx, auth)
	default:
		return nil, configpoc.ErrRecovery
	}
}

func (s *RoutedStoreSourceV3) resolveCompensationV3(ctx context.Context, p firewallipc.RoutedCompensationV3) (configpoc.RoutedCompensationAuthorizationV1, error) {
	generation, err := strconv.ParseUint(p.Reference.Generation, 10, 64)
	if err != nil {
		return configpoc.RoutedCompensationAuthorizationV1{}, configpoc.ErrRecovery
	}
	work := configpoc.RoutedWorkReferenceV1{Work: p.Reference.Work, Lineage: p.Reference.Lineage, Generation: generation}
	return s.reader.ResolveCompensationV1(ctx, p.Selection, p.Operation, work)
}

func (s *RoutedStoreSourceV3) resolveConsumedCompensationV3(ctx context.Context, prepared configpoc.RoutedCompensationAuthorizationV1, selected configpoc.SelectionReferenceV2) (configpoc.RoutedCompensationAuthorizationV1, error) {
	return s.reader.ResolveConsumedCompensationV1(ctx, prepared, selected)
}

func (a *RoutedRemoteAuthority) PrepareCompensationV3(ctx context.Context, work configpoc.RoutedWorkReferenceV1, selected configpoc.SelectionReferenceV2, operation string) (string, error) {
	value, err := a.client.Call(ctx, "prepare_recover", compensationRequestV3(work, selected, operation, ""))
	return value.Compensation.Ticket, err
}

func (a *RoutedRemoteAuthority) RecoverCompensationV3(ctx context.Context, work configpoc.RoutedWorkReferenceV1, selected configpoc.SelectionReferenceV2, operation, ticket string) error {
	if ticket == "" {
		return configpoc.ErrRecovery
	}
	_, err := a.client.Call(ctx, "recover", compensationRequestV3(work, selected, operation, ticket))
	return err
}

func compensationRequestV3(work configpoc.RoutedWorkReferenceV1, selected configpoc.SelectionReferenceV2, operation, ticket string) firewallipc.RoutedCompensationV3 {
	return firewallipc.RoutedCompensationV3{
		Reference: firewallipc.RoutedReferenceV3{Work: work.Work, Lineage: work.Lineage, Generation: strconv.FormatUint(work.Generation, 10)},
		Selection: selected, Operation: operation, Ticket: ticket,
	}
}
