# Fresh paired observation

The experimental routed adapter derives the current revision and owned-state
reference from one complete semantic observation under the same engine lock.
The four DHCP opening verification phases remain independent and fresh. No
result is cached across phases or RPCs. The common path uses four complete
policy observations instead of eight. At most two matching contextual references
are returned from that same observation and exact selected plan. A Before/Target
alias requires byte-identical canonical physical predicates under the same
dependencies; otherwise it is denied. No separate matching read can mix A→B→A
states into a false proof.

The RPC entry requires the optional paired engine interface, propagates the
remaining caller context, and cancels Group/Engine lock waits. Legacy Current
retains its one-second budget. No lease, confirmation or three-second RPC
deadline is extended. Physical drift and uncertain effects remain fail-closed.
Arbitrary filesystem/kernel I/O is not guaranteed preemptible; supervisor
containment remains necessary. Native restart performance qualification is
pending. This change creates no process, listener, worker, persistent data or
public API and changes no deployment unit.
