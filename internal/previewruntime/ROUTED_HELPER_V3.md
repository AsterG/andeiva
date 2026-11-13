# Read-only selected helper assembly

OpenRoutedHelperV3 is trusted supervisor assembly, not an administrative endpoint
or service activation. It borrows four pinned directory roots and opens only
read-only reserve descriptors. Expected pool identities, roles, 18-slot layouts
and capacities come from the supervisor; store/pool roots cannot alias.

The real process must have the exact helper UID and IPC primary group, only the
IPC/reader supplementary groups, NoNewPrivs, and exactly CAP_NET_ADMIN in all
five capability masks. The dedicated reader group must differ from the API
primary group and agree across all roots. Actual OS boot identity and network
namespace must match trusted metadata, with gateway distinct from host. Existing
v1/v2 process validators are unchanged.

The factory composes the existing selected reader, store source and v3 session.
It does not require a complete selected activation before the initial handshake:
a new writer may need that fencing handshake before publishing its authorized
boot-boundary intent. Every later effect still independently resolves selected
work, G1, reserves, scope and action. Merely opening this helper grants no plan.

Serve accepts only a supervisor-pinned inherited Unix channel and API PID and
reuses kernel peer credential validation. Controller disconnect leaves reader
and guardian lifetimes intact. Closing this runtime cancels channels and closes
its read-only pool descriptors, never the authority, namespace, listeners or
rules. Borrowed roots remain caller-owned. A compatibility v2 server in grouped
mode must separately be restricted to readback for its whole lifetime.

Tests use actual temporary shared-format files and verify newly opened pool FDs
are O_RDONLY, reject aliases/profile/identity/capability substitutions, and check
partial-open cleanup. Pure readiness fixtures do not impersonate the actual
helper process. A simulated engine/guardian proves disconnect/reader closure
does not replace its independent expiry; this is not native nftables evidence.
Full supervisor launch, three-process permissions, complete selected-store
transport and deployed units remain separate integration gates.

Linux: go test -race ./internal/previewruntime -run TestRoutedHelperV3 -count=1

The prepared `routedKernelV3` transport executes only the fixed nft executable
inside the already verified gateway namespace. Commands and the three table
names are fixed; generated batches arrive on standard input. Requests and both
output streams are bounded to 512 KiB, subprocesses to two seconds within the
caller deadline. Successful table-list absence is distinct from query failure;
presence alone never establishes ownership. The laboratory and helper reuse
the same pure presence decoder. Host execution and arbitrary enum dispatch are
rejected. This transport is not wired to a deployed unit; native process,
packet and resource qualification remain pending.

For the standalone kernel fixture, build the Linux test binary with
`go test -c -o /tmp/andeiva-preview.test ./internal/previewruntime`. In the
authorized Debian 13 lab, place that binary in a root-owned directory with mode
0700 and file mode 0500, then run
`bash packaging/preview/tests/routed-kernel-native.sh --isolated-lab /ABSOLUTE/PRIVATE/DIRECTORY/andeiva-preview.test` as root.
The harness creates three fresh namespaces, retains only their verified IDs for
cleanup and rejects CI. The opt-in test verifies native schema4 check/apply,
complete trusted readback, malformed-check preservation and rejection after the
launching thread leaves the gateway. Namespace anchors are close-on-exec.
It does not test packet traffic or the management/helper process identities.

Each nft subprocess receives `SIGKILL` if its pinned launching helper thread
dies. This limits descendants after an abrupt helper failure; it does not undo a
batch already accepted by the kernel. Recovery must still inspect effective
state and the selected transaction before admitting further writes.

The restricted empty-listener adapter cannot start or stop services. It accepts
only canonical configurations without enabled local services. Each observation
checks the pinned namespace and parses two complete captures of its kernel TCP
and UDP tables in IPv4 and IPv6. Missing tables, malformed data and any TCP
listener or bound UDP socket are refused. Established TCP connections are not
listeners. This adapter does not replace the separate listener worker/collector
required to enable a local service. The native fixture binds and closes each of
the four socket types and checks both refusal and subsequent observed absence.
