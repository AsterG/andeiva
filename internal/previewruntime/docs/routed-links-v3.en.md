# Owned gateway links

The root supervisor can construct two private-mode MACVLAN children directly in
its pinned, exclusively owned gateway namespace. Parent selection binds index,
name, MAC and MTU to current readback; no parent is moved or reconfigured. Child
MACs derive from the run identity. Children remain down and unaddressed: L3,
forwarding and policy activation belong to the transactional executor.

Creation requires an otherwise empty gateway (loopback only). Unexpected parent
changes, unknown links or uncertain creation acknowledgment fence further
creation. Cleanup removes only child identities positively observed after this
instance created them. Reused names/index changes never authorize deletion.
Uncertain leftovers require teardown of the supervisor-owned gateway namespace;
this component does not adopt another process's links or implement restart
recovery. The supervisor retains namespace descriptors through cleanup.

Unprivileged tests cover lifecycle, cancellation, foreign links, parent drift,
replacement identities and uncertain acknowledgments. The opt-in
`scripts/routed-links-native-isolated.sh` tests the real primitive in private
network/mount/PID namespaces with dummy parents. It requires a bounded root
systemd cgroup on disposable Debian 13, never a shared runner. A native pass does
not prove physical NIC support, DHCP, forwarding or product installation.
The root namespace producer additionally creates a fresh, non-adopted gateway
pin beneath an empty root:root 0700 directory. Mount targets use the retained
directory FD. Unshare runs on a dedicated locked thread; failed restoration
retires that thread. Fixed nsenter/sysctl operations configure only the new
namespace and read back forwarding-off and IPv6-disabled values before return.
Cleanup records detach/removal separately, so interruption after either effect
can be retried without deleting a replacement. The native harness injects both
cleanup interruptions and requires successful retries and an empty directory.
MNT_DETACH is not proof of process drainage: the supervisor must stop its cgroup
before releasing the namespace. Deployment/activation integration remains a
separate gate; no installed service is enabled by these constructors.