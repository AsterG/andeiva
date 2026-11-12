package authobservations

import (
	"context"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"
)

// Store owns only the newly classified anonymous observation area. Record never
// performs filesystem I/O. Flush/Close serialize persistence without holding the
// aggregation lock during filesystem operations.
type Store struct {
	mu                               sync.Mutex
	ioMu                             sync.Mutex
	root                             *os.Root
	lock                             *os.File
	policy                           Selection
	guard                            AdmissionGuard
	data                             snapshot
	peers                            int
	last                             time.Time
	persisted                        time.Time
	allocated                        uint64
	closed, degraded, dirty, unknown bool
	stopping                         bool
	uncertain                        bool
	memoryOnly                       bool
	cancel                           context.CancelFunc
	done                             chan struct{}
	closeOnce                        sync.Once
	closeErr                         error
	now                              func() time.Time
	hook                             func(string) error
	selectedDigest, policyDigest     string
}

func (s *Store) point(name string) error {
	if s.hook != nil {
		return s.hook(name)
	}
	return nil
}

// Admitted checks the explicit runtime selection before an auth constructor can
// switch classification. This does not retrofit support into an older binary.
func (s *Store) Admitted() error {
	if s == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.root == nil || s.guard == nil {
		s.mu.Unlock()
		return ErrUnavailable
	}
	policy, guard := s.policy, s.guard
	s.mu.Unlock()
	if guard.Selection(policy) != nil {
		return ErrUnavailable
	}
	return nil
}

// Record is called only after trusted authentication classified a failed,
// unverified login. A zero peer denotes an internal attempt without a socket;
// invalid peers are never converted into an address or an attacker label.
func (s *Store) Record(peer netip.Addr) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.stopping || s.now == nil {
		return
	}
	now := s.now().UTC()
	if now.Before(s.last) {
		increment(&s.data.Counters.ClockRejected, 1, &s.data.Counters)
		s.dirty, s.degraded = true, true
		return
	}
	s.last = now
	s.expire(now)
	minute := now.Truncate(time.Minute)
	if len(s.data.Intervals) == 0 || s.data.Intervals[len(s.data.Intervals)-1].Minute != minute {
		if len(s.data.Intervals) == maximumIntervals {
			s.evict(0, false)
		}
		s.data.Intervals = append(s.data.Intervals, Interval{Minute: minute, Created: now, Peers: []PeerCount{}})
	}
	i := &s.data.Intervals[len(s.data.Intervals)-1]
	if i.Total == ^uint64(0) {
		s.data.Counters.Saturated, s.dirty = true, true
		return
	}
	increment(&i.Total, 1, &s.data.Counters)
	if !validPeer(peer) {
		increment(&i.Overflow, 1, &s.data.Counters)
		increment(&s.data.Counters.Unattributed, 1, &s.data.Counters)
	} else {
		name := peer.Unmap().String()
		pos := sort.Search(len(i.Peers), func(j int) bool { return i.Peers[j].Peer >= name })
		if pos < len(i.Peers) && i.Peers[pos].Peer == name {
			increment(&i.Peers[pos].Count, 1, &s.data.Counters)
		} else if s.peers >= maximumPeers {
			increment(&i.Overflow, 1, &s.data.Counters)
		} else {
			i.Peers = append(i.Peers, PeerCount{})
			copy(i.Peers[pos+1:], i.Peers[pos:])
			i.Peers[pos] = PeerCount{Peer: name, Count: 1}
			s.peers++
		}
	}
	s.dirty = true
}

func (s *Store) evict(index int, expired bool) {
	i := s.data.Intervals[index]
	s.peers -= len(i.Peers)
	if expired {
		increment(&s.data.Counters.Expired, i.Total, &s.data.Counters)
	} else {
		increment(&s.data.Counters.CapacityEvicted, i.Total, &s.data.Counters)
	}
	s.data.Intervals = append(s.data.Intervals[:index], s.data.Intervals[index+1:]...)
	s.dirty = true
}

func (s *Store) expire(now time.Time) {
	for len(s.data.Intervals) != 0 && !now.Before(s.data.Intervals[0].Created.Add(MaximumAge)) {
		s.evict(0, true)
	}
}

func copyIntervals(in []Interval) []Interval {
	out := append([]Interval{}, in...)
	for i := range out {
		out[i].Peers = append([]PeerCount{}, in[i].Peers...)
	}
	return out
}

// Report never supplies expired detail, even if persistence is read-only. The
// owned worker flushes and rotates while this selected module is open. There
// are no workers in legacy auth, and Close joins this module's worker.
func (s *Store) Report() Report {
	if s == nil {
		return Report{Version: 1, Degraded: true, UnknownGap: true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now == nil {
		return Report{Version: 1, Degraded: true, UnknownGap: true}
	}
	now := s.now().UTC()
	if now.Before(s.last) {
		s.degraded = true
	} else {
		s.last = now
	}
	s.expire(now)
	return Report{Version: 1, Intervals: copyIntervals(s.data.Intervals), Counters: s.data.Counters, PersistedThrough: s.persisted, UnknownGap: s.unknown || s.dirty, Degraded: s.degraded || s.closed, Pending: s.dirty, AllocatedBytes: s.allocated, AllocatedKnown: !s.memoryOnly, MemoryOnly: s.memoryOnly}
}

// Flush publishes a bounded aggregate snapshot. Failure never becomes a fake
// audit success; it leaves degraded collection visible and does not alter any
// protected audit reserve or authentication manager failure latch.
func (s *Store) Flush(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalid
	}
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	return s.flush(ctx)
}

func (s *Store) flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.guard != nil && s.guard.Selection(s.policy) != nil {
		s.mu.Lock()
		s.degraded = true
		s.mu.Unlock()
		return ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.uncertain || s.memoryOnly || s.now == nil || s.root == nil || s.guard == nil {
		s.mu.Unlock()
		return ErrUnavailable
	}
	now := s.now().UTC()
	if now.Before(s.last) {
		s.degraded = true
		s.mu.Unlock()
		return ErrUnavailable
	}
	s.last = now
	s.expire(now)
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	if s.data.Generation == ^uint64(0) {
		s.degraded = true
		s.mu.Unlock()
		return ErrLimited
	}
	next := s.data
	next.Generation++
	next.At = now
	next.Intervals = copyIntervals(s.data.Intervals)
	s.dirty = false
	s.mu.Unlock()
	allocated, touched, err := s.publish(ctx, next)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.uncertain = touched
		s.dirty, s.degraded, s.unknown = true, true, true
		return err
	}
	s.data.Generation = next.Generation
	s.data.At = next.At
	s.persisted = next.At
	s.allocated = allocated
	return nil
}

// Close does not pretend that failed persistence was completed. The caller owns
// the os.Root and can reopen only through the selected-format admission path.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.stopping = true
		cancel, done := s.cancel, s.done
		s.mu.Unlock()
		if cancel != nil {
			cancel()
			<-done
		}
		s.ioMu.Lock()
		defer s.ioMu.Unlock()
		s.closeErr = s.flush(context.Background())
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		if s.lock != nil {
			if e := s.lock.Close(); s.closeErr == nil {
				s.closeErr = e
			}
		}
	})
	return s.closeErr
}

func (s *Store) start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.done = cancel, make(chan struct{})
	go func() {
		defer close(s.done)
		for {
			s.mu.Lock()
			delay := time.Minute
			if len(s.data.Intervals) > 0 {
				until := s.data.Intervals[0].Created.Add(MaximumAge).Sub(s.now())
				if until < delay {
					delay = until
				}
			}
			s.mu.Unlock()
			if delay < time.Millisecond {
				delay = time.Millisecond
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				_ = s.Flush(ctx)
			}
		}
	}()
}
