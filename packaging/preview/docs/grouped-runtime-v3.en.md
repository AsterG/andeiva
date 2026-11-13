# Grouped runtime integration

The package contains fixed supervisor-child roles and the explicit integrity
preparer. Their presence does not activate the grouped runtime or migrate an
existing installation. Existing units continue using their configured mode.
Do not execute internal child roles manually: inherited descriptors, an
authenticated root parent and the matching role credentials are mandatory.

The production factory uses the existing provisioned accounts, protected audit,
TLS certificate, authorized management address and real web assets. It opens
one v2 writer, with independently verified read-only helper pools. It never
opens a concurrent v1 configuration writer or invents a startup configuration.
Local listeners remain disabled in this initial grouped profile.

The supervisor must supply the management listener explicitly. Only the API
receives that listening socket; only the helper receives its private integrity
directory. The API verifies its exact address, device binding and network
namespace cookie. TLS and source-network restrictions remain enforced.
Listener availability permits recovery/confirmation requests; qualification
health separately requires full integrity readiness and actual idle readback.
Pending, uncertain or reconciling state must not be reported as qualified.

## Remaining offline installation gate

The deployment loader and offline migration are not installed by this change.
Their next implementation must:

1. Stop the previous configuration writer and prove its lock is released.
   Preserve its store, Running, Startup, Candidate, history and credentials.
2. Validate actual source schema and stable account subjects. Unsupported or
   unresolved source state must be refused, with the original evidence intact.
3. Prepare the v2 store and three exact shared reserve profiles through the
   approved migration APIs, under the writer identity. Keep protected audit.
4. Opt in to the approved grouped/deadline/shared-reader features explicitly.
   Close the writer before the final ownership/permission transition.
5. Pin distinct store/pool roots, exact device/inode reader descriptors, the
   explicit approved write budget and bounded read budget. Do not derive a
   larger budget silently or infer readiness from a root-owned manifest.
6. Explicitly prepare the helper-owned 0700 integrity directory through the
   capless preparer. An existing or incomplete marker is not reset or repaired.
7. Provide a new authorized isolated namespace with two real compatible links.
   Never reuse the old pre-addressed fixture as an empty baseline or remove
   its rules to make preparation succeed. No host routes or interfaces change.
8. Launch the authenticated roles and complete full inspection, authorized
   Startup boot and actual kernel readback before declaring qualification.
   On failure, preserve evidence and the previous deployment for recovery.

Reproducible build/static-package checks verify packaged files and boundaries;
they do not prove migration, native boot or end-to-end traffic qualification.

Child readiness has a separate 45-second startup/drain bound, accommodating the 30-second full inspection. Effect RPCs remain limited to three seconds. Persisted confirmation deadlines and Boot Started+10 seconds are unchanged. The factory retains its initial full graph validation; qualification is not inferred from a bound socket.
