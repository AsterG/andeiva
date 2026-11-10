# Kernel listener ownership collector

This read-only package belongs to the trusted laboratory supervisor. It adds no
helper capability, runs no command, changes no namespace or network setting,
and does not assign a service owner from a socket's UID alone. Production use is
limited to the Debian AMD64 laboratory; other operating systems fail closed.

`New(child, expected)` requires root, a directly owned child process, nonzero
API UID/GID, a distinct expected gateway namespace, and 32-character lowercase
hex run/instance IDs with a nonzero generation. The expected host namespace must
match the supervisor's actual current namespace. The collector retains an
`os.Root` for `/proc/<child>` and records the process start time. It verifies
parent PID, all four UID/GID values, namespace and start time. Subsequent reads
use this retained directory, not a newly resolved PID path. The supervisor must
retain the supplied `os.Process`; zero-signal liveness checks deliver no signal
and add the process handle's identity check before/after collection. The caller
must not release that handle while the collector is in use. The supervisor must
create a new collector for a replacement process and must never reuse an old
instance/generation as a successful observation after restart.

`Observe()` accepts no paths, PIDs, interfaces or commands. It reads bounded
`net/tcp`, `tcp6`, `udp`, `udp6`, `stat`, `status` and the child's numeric FD
directory. It reads, without following, only fixed namespace and FD symlinks.
TCP LISTEN rows and all bound UDP rows are correlated with socket inodes actually
held by the retained child. Same UID and endpoint without an owned FD is foreign,
not an owned listener. A matching inode with the wrong UID fails verification.
Established TCP connections are outside this listener collector; session closure
must be checked by the protocol lifecycle separately.

The result carries the run/instance/generation, namespace, start time, owned
`Sockets` and separate `Foreign` sockets. Records contain protocol, address
family, address, port, inode, UID and explicit wildcard/mapped flags. A consumer
must reject foreign, wildcard, mapped or unexpected listeners before confirming
a revision. No service ID or owner is fabricated: the trusted coordinator must
project exact endpoints onto the expected canonical revision. Raw process and
kernel evidence is internal supervisor information, not an ordinary-admin API.

Two captures must have identical process identity, listener tables and inode
ownership. Each is bracketed by process identity checks. Descriptor numbers and
sockets absent from the relevant tables do not define listener identity: accepted
TCP connections may open and close without changing a listener. If an enumerated
FD disappears before its link is read, only ENOENT is tolerated. It supplies no
ownership evidence; any retained listener row without an owned inode remains
foreign. Lost listener ownership between captures is rejected, as are changed
listener tables, PID/namespace/UID changes, other FD read errors, malformed or
ambiguous tables, duplicate inode/tuple (including IPv4-mapped IPv6 aliases), and
resource limit violations. Dynamic queue counters and established TCP connections
are parsed but are not listener state. Listener changes can still produce
transient rejection; callers
may retry within a bounded transaction deadline, but must not confirm on error.

An inherited recovery socket in the host namespace is absent from the gateway
tables and is therefore not misrepresented as a managed gateway listener. This
does **not** verify the recovery endpoint: the supervisor must separately bind
and verify that exact retained descriptor and its authenticated recovery proof.

Limits are 256 KiB per socket table, 64 KiB per process identity file, 1,024 rows
per table and at most 1,024 relevant sockets across tables, and 2,048 descriptors.
Access restrictions such as proc visibility or ptrace permissions cause failure;
there is no privilege-escalating fallback or SYS_PTRACE requirement. Whether the
root supervisor can inspect the actual unprivileged child in the Debian service
configuration remains a native integration gate.

```sh
go test ./internal/localobserve
go test -race ./internal/localobserve
go vet ./internal/localobserve
```

Parser tests cover byte ordering, mapped/wildcard addresses, malformed tables,
foreign ownership, changed inodes, identity changes and unstable captures. Linux
tests read only their own process and real loopback TCP/UDP sockets through a
private test constructor; they do not relax production admission or exercise
cross-process Debian service permissions. These tests do not prove appliance
recovery, kernel rule enforcement, or production readiness.
