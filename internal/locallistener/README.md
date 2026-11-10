# Managed listener lifecycle

This component binds the exact validated addresses and high TCP ports from the
local-service revision. The caller must already run under the unprivileged API
identity in the owned namespace. It validates actual interface/address presence;
it does not enter namespaces, change routes or execute a command.

The runtime factory creates real HTTPS or restricted SSH protocol servers with
the immutable configuration envelope hash. This is the `ActivationHash` used in
post-change connectivity proofs. An old handler cannot learn a later hash from
shared mutable state.

Replacement immediately calls `Stop` and closes sockets; joining in-flight
commands happens outside the activation callback. Otherwise a command retiring
its own listener would deadlock waiting for itself. Draining is bounded by the
server command deadlines and a limit on outstanding retired workers. A transient
drain is reported separately from listening access. Final process shutdown must
call `Close` outside any admitted transaction and join those workers.

`Registry` describes active server instances and is not kernel evidence. A trusted
supervisor collector must independently correlate process descriptors, socket
inodes, UID, network namespace and TCP/UDP tables. The activation engine may publish
a verified revision only after that comparison and nftables readback succeed.

Loopback tests exercise real socket replacement and occupied-port recovery without
network-administration privileges. They do not prove namespace isolation, HTTPS
authentication, SSH authentication or Debian packet filtering.
