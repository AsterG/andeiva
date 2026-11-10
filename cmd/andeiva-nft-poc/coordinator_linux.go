package main

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

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
	s := scanner(os.Stdin)
	var lease string
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
			err = nil
			if m.Request.Operation == configpoc.OpStage && m.Request.Config != nil {
				err = engine.Validate(*m.Request.Config)
			}
			if err == nil && m.Request.Operation == configpoc.OpCommit && m.Request.ConfirmFor > 0 {
				var snap configpoc.Snapshot
				snap, err = svc.Execute(ctx, actor, m.Surface, configpoc.Request{Operation: configpoc.OpStatus})
				if err == nil && (snap.Candidate == nil || snap.Generation != m.Request.ExpectedGeneration) {
					err = configpoc.ErrConflict
				}
				if err == nil {
					lease = m.Request.Key
					_, err = ch.call(message{Verb: "arm", Lease: lease, Previous: snap.Running, Revision: snap.Candidate.Revision, TTL: m.Request.ConfirmFor})
				}
			}
			if err == nil {
				r.Snapshot, err = svc.Execute(ctx, actor, m.Surface, m.Request)
			}
			if err == nil && m.Request.Operation == configpoc.OpConfirm {
				_, err = ch.call(message{Verb: "confirm", Lease: lease, Revision: r.Snapshot.Running})
				if err != nil {
					r.Snapshot.RecoveryRequired = true
				}
			}
		case "history":
			r.Audit, err = svc.History(actor)
		case "authority":
			var response reply
			response, err = ch.call(message{Verb: "authority"})
			r.State = response.State
		case "recover":
			err = svc.Close()
			if err == nil {
				svc, err = configpoc.Open(dir, engines, configpoc.Options{})
			}
			if err == nil {
				_, err = ch.call(message{Verb: "recover"})
			}
		case "fail-next-component":
			fault.FailNext("after")
			err = nil
		case "concurrent":
			// Same generation from two clients; exactly one save may publish a receipt.
			results := make(chan error, 2)
			for i := 0; i < 2; i++ {
				req := m.Request
				req.Key += strconv.Itoa(i)
				go func() { _, e := svc.Execute(ctx, actor, configpoc.API, req); results <- e }()
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
		if err != nil {
			r.Error = err.Error()
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
