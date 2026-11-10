# Local services: isolated Debian laboratory

This runner is experimental. It does not install a permanent appliance service
or change host SSH, host firewall, NAT, routes or physical interfaces. Use only
an authorized Debian 13 AMD64 VM with a tested recovery snapshot. Keep its
console available. Never run privileged network tests on shared CI runners.

## Build and provision

On the build machine, use the repository's pinned toolchain and lockfile:

```sh
go test -race ./internal/localruntime ./internal/localadmin ./internal/localengine ./internal/localobserve
go vet ./cmd/... ./internal/...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o andeiva-local-lab ./cmd/andeiva-local-lab
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o andeiva ./cmd/andeiva
cd frontend
npm ci --ignore-scripts --no-audit --no-fund
npm run build
```

Transfer the binaries and `frontend/dist` by an authorized local method. Verify
SHA-256 checksums after transfer. Place them in a root-owned directory readable
by the dedicated API account and executable by the helper. Do not place binaries
inside the private runtime state directory. Never transfer operator credentials
through command-line arguments, logs or a public artifact.

Provision two dedicated system accounts with different nonzero UIDs/GIDs,
non-login shells and no supplementary groups. Do not reuse installed Alpha
accounts. A root-owned mode-0600 JSON file selects the existing LAN address,
interface, authorized client CIDR, account names and frontend location:

```json
{
  "lan_address": "198.51.100.10",
  "lan_interface": "ens34",
  "allowed_cidr": "198.51.100.2/32",
  "api_user": "andeiva-local-api",
  "api_group": "andeiva-local-api",
  "helper_user": "andeiva-local-helper",
  "helper_group": "andeiva-local-helper",
  "web_root": "/opt/andeiva-local-lab/dist"
}
```

The documentation addresses are examples, not addresses to add to the host.
Replace them with explicitly authorized existing LAN values. Both the selected
address and loopback must have TCP 18443 free. No wildcard or WAN fallback exists.
As root in the VM, with the binary on PATH:

```sh
andeiva-local-lab provision /var/tmp/andeiva-local-example01 /root/lab-config.json
andeiva-local-lab run --snapshot-confirmed /var/tmp/andeiva-local-example01
```

The state directory must not already exist on first provision. Repeating
provision validates existing configuration; it never regenerates credentials.
The runner does not create OS accounts. Provisioning generates a short-lived
laboratory TLS CA and certificate, an SSH host key and independent operator
credentials. Protect `operator/{admin-a,admin-b,viewer}.json` as root 0600.
The certificate is valid for 24 hours; certificate lifecycle automation is not
implemented here. Trust only the generated CA in a disposable test client profile.

## Web, CLI and API

Open `https://<authorized-LAN-address>:18443/local-services`. Sign in with the
provisioned administrator's username and credential. Light is the default; Dark
is opt-in. The LAN recovery address is fixed and cannot be edited by this page.

Enable HTTPS or SSH, select a fixture interface and address, choose a TCP port
above 1023 and explicit authorized source CIDRs. The managed addresses belong
only to the source/gateway/sink namespaces. Stage the candidate, Validate and
Commit with a confirmation window. The existing revision is not saved to Startup
until Save is explicitly requested.

Confirmation requires authenticated proofs from every enabled binding. Use the
runner's typed `probe` operation, documented in the parent README, with the
pending generation, target hash and lease from the administrative response.
Use the same administrator as the pending owner. HTTPS probes validate the CA;
SSH probes validate the exact host key. Proof files are private and short-lived.
Enter their tokens in the confirmation form before the deadline. Do not log or
capture that form while it contains tokens. Disabling all managed services needs
only the recovery proof collected by the interface.

CLI discovery and a read-only request use the same runtime:

```sh
andeiva local-services --help
andeiva local-services status --url https://127.0.0.1:18443 \
  --ca-file /var/tmp/andeiva-local-example01/ca.crt \
  --credentials-file /var/tmp/andeiva-local-example01/operator/admin-a.json
```

Web, CLI and API share `/api/v1/local-services`, its transaction/history routes
and `/api/v1/effective-policies`. Use generation checks and stable request keys;
after an uncertain response, read status instead of issuing a new mutation key.
Viewers may read status/effective policy but cannot write or retrieve audit history.
Rules in Effective Policies are generated and cannot be edited directly.

## Failure tests and cleanup

From a second authorized root console:

```sh
andeiva-local-lab check /var/tmp/andeiva-local-example01
andeiva-local-lab fault /var/tmp/andeiva-local-example01 api-kill
andeiva-local-lab check /var/tmp/andeiva-local-example01
andeiva-local-lab stop /var/tmp/andeiva-local-example01
```

Also test helper-kill and an unconfirmed change with api-pause. Collect the
before/after run, instance, lifecycle generation, configuration generation and
revision hashes. Verify actual traffic after recovery; a successful API response
alone is insufficient. Reset recreates the owned fixture and interrupts service;
it is not uninterrupted dataplane operation. Three resets and 128 probes per
supervisor bound the experiment. Restarting the supervisor preserves its journal;
do not delete state to hide a failed recovery.

Same-OS-boot recovery retains confirmed Running, including unsaved changes;
a genuine OS boot restores Startup. Missing/corrupt boot metadata with existing
journal blocks startup. An unconfirmed revision must restore its verified
predecessor. Check listeners, rules, audit and IPv4/IPv6 authorized/denied traffic.
Distinguish timeout from refused connection, TLS, host-key or authentication errors.

Stop releases only owned processes, namespaces and recovery sockets. Compare
host rules/interfaces/routes with the baseline and check installed services.
Retain protected state and evidence until reviewed. Remove only the explicitly
created laboratory directory/accounts after confirming no process uses them.
Never flush the host ruleset or delete another experiment's network resources.
