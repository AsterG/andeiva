package main

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type helperCaller interface {
	call(message) (reply, error)
}

// All coordinator mutation paths share this lock. The config journal records
// its own durable confirm, while blocked tracks the separate helper boundary.
type coordination struct {
	mu      sync.Mutex
	svc     *configpoc.Service
	helper  helperCaller
	engine  configpoc.Engine
	lease   string
	blocked bool
}

func (c *coordination) execute(ctx context.Context, actor configpoc.Principal, surface configpoc.Surface, req configpoc.Request) (configpoc.Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blocked && req.Operation != configpoc.OpStatus {
		return configpoc.Snapshot{RecoveryRequired: true}, configpoc.ErrRecovery
	}
	if req.Operation == configpoc.OpStage && req.Config != nil {
		if err := c.engine.Validate(*req.Config); err != nil {
			return configpoc.Snapshot{}, err
		}
	}
	if req.Operation == configpoc.OpCommit && req.ConfirmFor > 0 {
		snap, err := c.svc.Execute(ctx, actor, surface, configpoc.Request{Operation: configpoc.OpStatus})
		if err != nil {
			return snap, err
		}
		if snap.Candidate == nil || snap.Generation != req.ExpectedGeneration {
			return snap, configpoc.ErrConflict
		}
		c.lease = req.Key
		if _, err = c.helper.call(message{Verb: "arm", Lease: c.lease, Previous: snap.Running, Revision: snap.Candidate.Revision, TTL: req.ConfirmFor}); err != nil {
			return snap, err
		}
	}
	snap, err := c.svc.Execute(ctx, actor, surface, req)
	if err == nil && req.Operation == configpoc.OpConfirm {
		// Latch before contacting the helper. A rejected or lost acknowledgment
		// must not leave any path that can save the provisional revision.
		c.blocked = true
		var acknowledgment reply
		acknowledgment, err = c.helper.call(message{Verb: "confirm", Lease: c.lease, Revision: snap.Running})
		if err == nil && !confirmed(acknowledgment, c.lease, snap.Running.Hash) {
			err = errProtocol
		}
		if err == nil {
			c.blocked = false
		} else if authority, queryErr := c.helper.call(message{Verb: "authority"}); queryErr == nil && confirmed(authority, c.lease, snap.Running.Hash) {
			if current, readErr := c.helper.call(message{Verb: "current"}); readErr == nil && current.Hash == snap.Running.Hash {
				c.blocked = false
				err = nil
			}
		}
	}
	snap.RecoveryRequired = snap.RecoveryRequired || c.blocked
	return snap, err
}

func confirmed(r reply, lease, hash string) bool {
	return lease != "" && r.State.Phase == "idle" && r.State.ID == lease && r.State.Target == hash
}

func coordinator(runID, dir, sequence, namespace string) error {
	if os.Geteuid() == 0 {
		return errProtocol
	}
	base, err := strconv.ParseUint(sequence, 10, 64)
	if err != nil {
		return err
	}
	expected, err := strconv.ParseUint(namespace, 10, 64)
	if err != nil || expected == 0 {
		return errProtocol
	}
	writer := os.NewFile(3, "guardian-request")
	reader := os.NewFile(4, "guardian-response")
	defer writer.Close()
	defer reader.Close()
	ch := &channel{run: runID, seq: base, out: writer, input: reader, in: scanner(reader), expectedNamespace: expected}
	engine := &remoteEngine{ch}
	fault := configpoc.NewSimEngine("fault-injection")
	engines := []configpoc.Engine{engine, fault}
	svc, err := configpoc.Open(dir, engines, configpoc.Options{})
	if err != nil {
		return err
	}
	// Reconcile the durable journal before clearing an expired authority barrier.
	// A durable confirm whose helper acknowledgment was lost may require manual
	// recovery; it must never revive an expired provisional revision on Open.
	if _, err = ch.call(message{Verb: "recover"}); err != nil {
		_ = svc.Close()
		return err
	}
	defer func() {
		if svc != nil {
			_ = svc.Close()
		}
	}()
	actor := configpoc.Principal{ID: "lab-operator", Role: configpoc.RoleAdmin}
	control := &coordination{svc: svc, helper: ch, engine: engine}
	s := scanner(os.Stdin)
	var last uint64
	for s.Scan() {
		var m message
		if err = decode(s.Bytes(), &m); err != nil {
			return err
		}
		if m.Run != runID || m.Sequence <= last {
			return errProtocol
		}
		last = m.Sequence
		r := reply{Run: runID, Sequence: m.Sequence}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		switch m.Verb {
		case "execute":
			r.Snapshot, err = control.execute(ctx, actor, m.Surface, m.Request)
		case "history":
			r.Audit, err = svc.History(actor)
		case "authority":
			var response reply
			response, err = ch.call(message{Verb: "authority"})
			r.State = response.State
		case "recover":
			if control.blocked {
				err = configpoc.ErrRecovery
				r.Snapshot.RecoveryRequired = true
				break
			}
			err = svc.Close()
			if err == nil {
				svc, err = configpoc.Open(dir, engines, configpoc.Options{})
			}
			if err == nil {
				_, err = ch.call(message{Verb: "recover"})
			}
			control.svc = svc
		case "fail-next-component":
			fault.FailNext("after")
			err = nil
		case "concurrent":
			if control.blocked || m.Request.Operation != configpoc.OpSave {
				err = configpoc.ErrRecovery
				r.Snapshot.RecoveryRequired = true
				break
			}
			// Same generation from two clients; exactly one save may publish a receipt.
			results := make(chan error, 2)
			for i := 0; i < 2; i++ {
				req := m.Request
				req.Key += strconv.Itoa(i)
				go func() { _, e := control.execute(ctx, actor, configpoc.API, req); results <- e }()
			}
			a, b := <-results, <-results
			if (a == nil) == (b == nil) {
				err = errProtocol
			} else {
				err = nil
			}
		default:
			err = errProtocol
		}
		cancel()
		r.Snapshot.RecoveryRequired = r.Snapshot.RecoveryRequired || control.blocked
		if err != nil {
			r.Error = err.Error()
		}
		// This trace records the coordinator/helper boundary separately from
		// History, whose confirm receipt describes only the durable journal.
		if e := json.NewEncoder(os.Stderr).Encode(map[string]any{
			"event": "coordinator_operation", "actor": actor.ID, "sequence": m.Sequence,
			"verb": m.Verb, "operation": m.Request.Operation, "surface": m.Surface,
			"recovery_required": r.Snapshot.RecoveryRequired, "error": r.Error,
		}); e != nil {
			return e
		}
		if e := json.NewEncoder(os.Stdout).Encode(r); e != nil {
			return e
		}
		if svc == nil {
			return errProtocol
		}
	}
	return s.Err()
}
