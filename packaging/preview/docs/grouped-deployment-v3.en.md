# Grouped deployment loader and supervisor

This assembly is experimental and is not enabled by package installation. The grouped units have no installation target. Do not enable them before offline migration, authenticated namespace provisioning and recovery qualification are complete.

The root supervisor reads only `/etc/andeiva-preview/grouped.json`. Its versioned resource manifest pins the account-file digest, four shared directory identities, three fixed reserve profiles and explicit reader/writer budgets. It does not contain policy or grant authority to apply it. The helper independently verifies the selected configuration and full integrity before ordinary mutations become available.

Resources under `/var/lib/andeiva-preview/grouped` and `/run/andeiva-preview/grouped` must already exist with their exact owners and modes. The loader creates no namespaces, accounts, policies or directories. Namespace pins must come from the trusted manager and match current boot/run identity. Existing preview namespaces and journal remain separate. A new prepared store must preserve existing policies and historical provenance through the offline migration contract; a fresh fixture is not an upgrade path.

The grouped management listener is inherited from its dedicated systemd socket; its exact configured address, device and host namespace are checked before child launch. No wildcard binding or caller-selected path is accepted. Its health socket is separate from the legacy API runtime directory. Listener availability does not mean integrity or data-plane qualification.

API process failures use a constant-memory restart budget: three attempts per minute, with three-second backoff. A failed restart or exhausted budget latches degraded administration and keeps the supervisor and helper alive. The existing guardian retains its original deadline. There is no automatic helper restart, integrity-fence reset or unsafe removal of a stale health socket. Operator recovery may be required. Explicit service stop still closes the children; helper failure is reported separately.

Source tests cover strict manifests, namespace descriptor type/identity and modeled restart exhaustion. They do not qualify systemd sandbox behavior, installation, real packet forwarding or permanent deployment. The units remain disabled until those gates pass.

The explicit `namespace_profile` is `host-gateway-v2`: metadata schema 2 requires only the real host and gateway namespaces. No source/sink test namespaces are created or accepted by this loader.
