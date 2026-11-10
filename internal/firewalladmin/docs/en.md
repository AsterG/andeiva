# Administrative firewall laboratory — English

Status: experimental implementation and reproducible procedure. Native integration,
live failure probes and resource measurements remain pending until recorded for
this exact revision. Do not treat these instructions as a production appliance guide.

## Preparation and versioned installation

Use a disposable Debian 13 VM with an authorized recovery snapshot. The literal
`--snapshot-confirmed` acknowledges that prerequisite; it does not create or verify
a hypervisor snapshot. Do not run the privileged lab on the Windows host, a customer
appliance or a shared production network. Go 1.27.3, the repository's pinned frontend
toolchain/dependencies, nftables 1.1.3 and the fixed tools `/usr/bin/ip`,
`/usr/bin/nsenter`, `/usr/bin/setpriv`, `/usr/sbin/nft` must already be available.
Build dependencies belong to the development environment; this procedure performs
no online appliance installation or package update.

The runtime uses numeric UID/GID **1001**, with no supplementary groups. Reserve
that identity for this lab. The operator uses numeric UID/GID **1000**, which owns
the generated credential files. These numbers are fixed by the experiment; named
accounts are not created. Do not reuse a service identity belonging to another workload.

Run the following from a reviewed repository checkout inside the lab. This is a
first installation into a new version directory, not an automatic upgrade. Executables,
web assets and their parent directories must be root-owned and not group/world writable.
The fixed web path must not already exist when creating its symlink. To change
versions, stop the lab and review both the executable and web target together;
these commands deliberately do not replace an existing link.

```bash
export GOTOOLCHAIN=local GOWORK=off
ARTIFACT_VERSION="$(git rev-parse --short=12 HEAD)"
BUILD_DIR=".tmp/admin-lab-build/$ARTIFACT_VERSION"
mkdir -p "$BUILD_DIR"
go build -trimpath -o "$BUILD_DIR/andeiva-admin-lab" ./cmd/andeiva-admin-lab
go build -trimpath -o "$BUILD_DIR/andeiva" ./cmd/andeiva
npm --prefix frontend run build
INSTALL_ROOT="/opt/andeiva-admin-lab/versions/$ARTIFACT_VERSION"
sudo install -d -o root -g root -m 0755 "$INSTALL_ROOT/web"
sudo install -o root -g root -m 0755 "$BUILD_DIR/andeiva-admin-lab" "$INSTALL_ROOT/andeiva-admin-lab"
sudo install -o root -g root -m 0755 "$BUILD_DIR/andeiva" "$INSTALL_ROOT/andeiva"
sudo cp -R frontend/dist/. "$INSTALL_ROOT/web/"
sudo chown -R root:root "$INSTALL_ROOT"
sudo chmod -R go-w "$INSTALL_ROOT"
sudo ln -s "versions/$ARTIFACT_VERSION/web" /opt/andeiva-admin-lab/web
```

No daemon, boot activation, host firewall rule or host forwarding change is installed.
The executable and web build must represent the same reviewed revision.

## Provisioning, TLS and login

```bash
LAB_DIR="$(sudo "$INSTALL_ROOT/andeiva-admin-lab" --provision)"
printf '%s\n' "$LAB_DIR"
sudo "$INSTALL_ROOT/andeiva-admin-lab" --run-lab --snapshot-confirmed "$LAB_DIR"
```

Keep this supervisor terminal open. In a second terminal use the printed directory;
it is generated under `/var/tmp`, not a caller-selected arbitrary state path.
Provisioning creates `admin-a.json`, `admin-b.json`, `viewer.json` as regular files,
mode `0600`, owner 1000. Each account has its own random 32-byte credential encoded
as 64 hexadecimal characters. `accounts.json` stores credential digests. There is
no default password, MFA, directory login or production identity lifecycle here.
Do not publish these files or paste their values into commands, logs or evidence.

The API and web UI listen only at **https://127.0.0.1:9443**, with TLS 1.3 minimum.
Open **https://127.0.0.1:9443/firewall** from the lab browser. Inspect the generated
`ca.crt` and import it only into a disposable lab browser trust profile before
connecting. Remove that temporary trust when finished. The CA and server certificate
expire after 24 hours; provision a new disposable run when they expire. There is no
CA private key file. Do not bypass certificate warnings or use insecure TLS flags.
The exact origin is `127.0.0.1:9443`; using `localhost` does not satisfy Host validation.
For a browser outside the VM, use an explicitly authorized loopback-only tunnel to
that exact origin; do not expose the listener on a physical interface.

Enter the username and credential from its protected file in the browser login.
`admin-a` and `admin-b` can mutate; `viewer` can inspect current state, but cannot
write or retrieve history. Sessions expire after 30 minutes, or 5 minutes idle.
Restarting the API invalidates its in-memory sessions. Login/audit failures fail
closed. The UI defaults to English and light mode; Spanish, Portuguese and explicit
dark mode are selectable. Edits remain local until Stage. Review Candidate, Running,
Startup and the last observed effective state separately. Refresh is manual.

## Official CLI and transaction flow

Run the CLI as UID 1000, not through `sudo`. Replace `<COMMIT>` and `<SUFFIX>` with
the installed version and printed directory. The client requires an explicit CA;
credential files must be owned by the executing user, regular, singly linked,
non-symlink files with mode 0600. Each command logs in and logs out without storing
a session token. Change `--lang en` to `es` or `pt` for localized messages.

```bash
INSTALL_ROOT="/opt/andeiva-admin-lab/versions/<COMMIT>"
LAB_DIR="/var/tmp/andeiva-admin-lab-<SUFFIX>"
fw() {
  "$INSTALL_ROOT/andeiva" --lang en firewall "$@" \
    --url https://127.0.0.1:9443 \
    --ca-file "$LAB_DIR/ca.crt" \
    --credentials-file "$LAB_DIR/admin-a.json"
}
fw status
fw list
```

Record the initial Running hash if you want to return to it. Save the JSON below
as `stage.json` in an operator-owned workspace. Replace **2** with the exact current
`snapshot.generation` from `fw status`; it is an example, not a fixed generation.
Use a new idempotency key for a new intended mutation. To retry the same request,
retain its original key and complete payload. Do not silently retry conflicts.

```json
{
  "operation": "stage",
  "key": "stage-service-01",
  "expected_generation": 2,
  "config": {
    "schema_version": 2,
    "default_action": "deny",
    "rules": [
      {
        "id": "tcp-service",
        "action": "allow",
        "match": {
          "source": "198.18.0.2/32",
          "destination": "198.18.0.6/32",
          "protocol": "tcp",
          "source_ports": {"from": 1, "to": 65535},
          "destination_ports": {"from": 18080, "to": 18080}
        }
      }
    ]
  }
}
```

```bash
fw stage --request-file stage.json
fw validate
fw commit --confirm-seconds 60
fw status
```

Before the deadline, use the supervisor's `probe tcp 18080` and check the resulting
`allowed` value. Confirm only the revision you reviewed. `fw confirm` obtains the
current generation and Running hash and binds the confirmation to them; a concurrent
change is rejected. The same administrator who committed must confirm. Omitting
confirmation restores the previous policy. The accepted interval is 30–120 seconds.
Plain `fw commit` commits without a confirmation interval. Neither form saves Startup.

```bash
fw confirm
fw save
fw history --limit 50
fw history --before <NEXT_BEFORE> --limit 50
fw rollback --target <EARLIER_REVISION_HASH>
fw status
```

Only use the history pagination command when `next_before` is nonzero; replace both
placeholders with returned values. Historical rollback changes Running, not Startup;
use `save` separately if that recovered revision should survive a complete restart.
Pending confirmation blocks other mutations. A second administrator cannot overwrite
another administrator's candidate or confirm their commit. `help`, unique command
abbreviations and `firewall completion` are available. A request file may supply an
explicit generation/key/target; `--request-file -` reads standard input.

The web editor performs the same stage, validate, commit, confirm, save and historical
rollback operations with operation/revision review. Array order is priority. A maximum
of 64 unique rule IDs is accepted. CIDRs must be canonical IPv4; protocol is `tcp` or
`udp`; both port ranges are inclusive, nonzero and bounded by 65535. There is no
arbitrary shell, executable, namespace, table or nft program input.

## Typed HTTPS contract

All JSON bodies are bounded to 65536 bytes; unknown or duplicate fields and malformed
values are rejected. Write operations require administrator authorization, a unique
`key` and `expected_generation`. `X-ANDEIVA-Client` is `web`, `cli` or `api`; it labels
audit origin and grants no privilege.

| Method and path | Request and result |
|---|---|
| `POST /api/v1/auth/login` | `{username, credential}`; web receives a Secure/HttpOnly/SameSite=Strict cookie and identity/CSRF; CLI/API also receive a bearer token |
| `GET /api/v1/auth/session` | Current identity, role, expiry and CSRF value |
| `POST /api/v1/auth/logout` | Empty object; invalidates the current token |
| `GET /api/v1/firewall` | `{snapshot, effective}`; revision states and bounded `{id, packets, bytes}` counters |
| `POST /api/v1/firewall/transactions` | `{operation, key, expected_generation, config?, confirm_for?, target?}`; returns current state |
| `GET /api/v1/firewall/history?before=0&limit=50` | Administrator-only `{revisions, audit, next_before}`; limit 1–100 |

`config` is present only for `stage`; `confirm_for` is a JSON integer in nanoseconds
for `commit` (60 seconds = `60000000000`); `target` is the exact Running hash for
`confirm` or a history-listed hash for `rollback`. Other operations are `validate`
and `save`. Browser writes require the exact Origin plus `X-CSRF-Token`; bearer
clients send `Authorization: Bearer TOKEN` and must not also send the session cookie.
Never persist tokens in browser storage or expose them in command arguments.

Effective states are `verified`, `pending_confirmation`, `recovery_required` or
`unavailable`. Verification means semantic readback matched Running at the last
observation, not ongoing monitoring or a security certification. Errors return
`{code, request_id}` with stable codes; invalid input is 400, denied identity 401,
forbidden operation 403, generation/replay/pending conflicts 409 and unavailable
recovery 503. Refresh and review before a new mutation after an ambiguous response.

## Isolated traffic and lifecycle

Three unnamed network namespaces contain source `198.18.0.2`, gateway and sink
`198.18.0.6`. Fixed TCP/UDP echo listeners use ports 18080–18082. The gateway owns
only `inet andeiva_admin`; `src0` and `dst0` select transit direction. Host addresses,
routes, rules and forwarding are not policy targets. The supervisor checks host
snapshots and an unrelated namespace sentinel.

The first matching rule wins; unmatched traffic and IPv6 are denied. Original
packets must match full current CIDRs, protocol, ports and interfaces and tracked
original new/established state. Accepted requests set an admission mark. Responses
require the reversed current tuple, established/reply state and that mark. There is
no global established acceptance. Deleting/narrowing a rule or placing a deny first
revokes matching responses; a current same-tuple allow intentionally permits an
already admitted connection. Counters total packets/bytes in both directions and
reset on replacement. They are not flow logs or packet captures.

Supervisor standard-input commands:

| Command | Behavior |
|---|---|
| `probe tcp 18080`, `probe udp 18080` | Original-direction echo test; ports 18080–18082 accepted |
| `probe-reverse tcp 18080`, `probe-reverse udp 18080` | Unsolicited reverse-direction test, not an established reply |
| `status` | Check host snapshot and unrelated sentinel |
| `kill-api` | Stop API; retain helper and current policy, with independent confirmation expiry |
| `restart-api` | Restart only when API is stopped; `Boot:false` resumes Running, with conservative pending/uncertain recovery |
| `kill-helper` | Failure injection: stop API and close the whole lab; expect an error, not ordinary success |
| `stop` or stdin EOF | Verify host/sentinel and clean owned processes/namespaces |

The supervisor has a 60-minute ceiling. Use `stop` for normal cleanup; do not use
force-kill as a substitute for checked shutdown. `kill-helper` tests emergency
closure, not dataplane continuity. Starting `--run-lab --snapshot-confirmed` again
with the same directory is a complete `Boot:true` start that selects saved Startup.
Journals and authentication audit remain on disk; preserve evidence before retiring
the disposable VM. Never erase a journal to make recovery pass. Review the generated
`report-<run>.json`, operations log and audit under appropriate permissions; they
are local evidence, not public API output. Verify cleanup and host invariance before
claiming success. Remove temporary browser trust after shutdown.

## Validation and limitations

```bash
go test -race ./internal/configpoc ./internal/firewalladmin ./internal/adminauth ./internal/adminapi ./internal/adminclient ./internal/cli ./internal/firewallipc ./internal/firewallnft ./internal/nftengine ./internal/nftpoc ./internal/nftguardian ./cmd/andeiva-admin-lab
go vet ./...
go build ./...
bash scripts/check-firewall-admin.sh
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
docker build -f frontend/Dockerfile.visual -t andeiva-design-check .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true --shm-size=512m andeiva-design-check
```

These are reproducible commands, not a claim that every gate was executed. Container
checks build/test source and UI; the privileged lab is not a Docker Compose or
EKS/Helm deployment. No EKS/Helm runtime or service manifests are added.

For each authorized native run record the exact source/artifact hash, Debian/nft
versions privately, default deny, allowed request/reply, unsolicited reverse denial,
rule deletion/narrowing/order, TCP and UDP, staged-versus-effective separation,
rollback, confirmation expiry during API loss, API restart, saved Startup/full restart,
viewer denial, stale generations, session expiry, helper emergency closure, host
invariance and cleanup. Measure CPU, peak RSS, journal size and elapsed time from
real evidence. The supervisor report supplies some of these values; it is not a
capacity benchmark by itself. No native result or resource target is asserted here.

No IDS/IPS, antivirus, WAF, TLS inspection, DNS filtering, NAT, VPN, AD SSO, MFA,
HA or customer appliance installer is implemented by this flow. Unknown production
traffic may never use this laboratory's permissions to bypass required identity or
inspection. The prior fixed-catalog nftables POC remains a separate schema 1 path.
