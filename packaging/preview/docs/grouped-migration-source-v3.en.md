# Cold-migration source inspection

The cold installer must stop the legacy API and its socket while retaining the old helper and namespace manager. Core migration holds both source journal locks until selected publication. The source verification callback does not substitute for these locks or the exact source fingerprints.

Two fixed child roles inspect the retained source: a capability-free API identity performs only state/observe/state against the authenticated legacy helper; a NET_ADMIN-only helper identity enters the pinned old gateway and verifies the complete firewall observation against all imported rules. Managed local and routed tables must be genuinely absent. The initial profile requires no local-service declarations; it does not attribute foreign listeners to ANDEIVA.

The parent executes the guardian probe before and after semantic kernel inspection. Both observations require idle and the same actual helper PID and unchanged lease receipt. Historical idle IDs, targets and deadlines are retained, not reset. Neither role invokes Recovered, Apply, Arm or Confirm. A read-only legacy handshake advances its controller epoch; subsequent legacy restart still follows ordinary recovery.

Requests are bounded to 64 KiB; replies to 4096 bytes. Fixed roles use inherited namespace FD3, root-owned request pipes, root-parent checks and parent-death signals. No caller-selected executable, namespace path or command is accepted. Read failures, helper replacement, nonidle phase, changed policy or changed receipt reject migration.

Tests use a simulated kernel with real compilers and semantic verification, plus modeled read-only guardian responses. They do not establish successful cross-identity execution, migration installation or actual kernel qualification. The permanent deployment remains disabled until the complete offline migration, boot and recovery gates pass.

The conservative source profile also reads bounded `/proc/net/tcp`, `tcp6`, `udp` and `udp6` inside that gateway before and after inspection. It refuses TCP LISTEN entries or any UDP endpoint, including foreign ones. This is an empty-INET-listener precondition, not process ownership attribution. Malformed, unavailable or oversized tables refuse migration. Each child remains pinned to its creating OS thread through Start and Wait; unit tests exercise thread identity and later worker-thread retirement, not a native migration process.
