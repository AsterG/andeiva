# Firewall Alpha Preview — English

Experimental Debian 13 AMD64 / VMware installation. Enforcement uses isolated
namespaces; it does not protect the host or route production traffic. Keep a VM
recovery snapshot. See [runtime boundaries](../README.md) before installation.

## Install and provision

Download the `firewall-alpha-preview-debian13-amd64` artifact from an approved
Quality run in the private repository. Artifacts expire after three days. Compare
the run commit with the reviewed PR and check `SHA256SUMS`; a checksum is not a
publisher signature. Transfer through an authorized channel. Required Debian tools
must already be installed; the package does not download dependencies.

```bash
sha256sum -c SHA256SUMS
sudo dpkg -i ./andeiva-firewall-preview_0.1.0~alpha<BUILD>_amd64.deb
sudo install -o root -g root -m 0644 \
  /etc/andeiva-preview/config.json.example /etc/andeiva-preview/config.json
sudoedit /etc/andeiva-preview/config.json
```

Replace `<BUILD>` with the downloaded version. Configure the actual LAN IPv4
address/port, LAN interface and an explicit authorized client source prefix.
`192.0.2.1` and `CHANGE_ME` are placeholders. The client prefix is independent of
the server address; use a client `/32` when only one workstation needs access.
Do not select WAN for the initial preview. Keep the supplied service-account names.

```bash
sudo /usr/lib/andeiva-preview/andeiva-preview provision
sudo systemctl daemon-reload
sudo systemctl enable --now andeiva-preview.target
sudo /usr/lib/andeiva-preview/andeiva-preview health
sudo systemctl status andeiva-preview.target \
  andeiva-preview-api.service andeiva-preview-helper.service \
  andeiva-preview-namespaces.service --no-pager
```

Provisioning never silently replaces an existing installation. Partial or invalid
state blocks; preserve it for diagnosis. The marker, credentials and TLS files
survive upgrades. Service identities are separately allocated and checked.

## Access and administer

On an authorized LAN client, explicitly trust the CA from
`/var/lib/andeiva-preview/ca.crt` after verifying its provenance. This procedure
does not install trust in Windows or alter client routing. Use the exact configured
HTTPS address and open `/firewall`. Do not disable certificate verification.

Initial operator credentials are root-only JSON files under
`/var/lib/andeiva-preview/operator/`: `admin-a`, `admin-b` and `viewer`. Obtain the
selected credential privately from the VM console; never paste it into logs,
issues or support bundles. The viewer cannot change policy or read protected
history. Authentication is experimental; production MFA is not implemented.

The installed CLI is `andeiva`. A Linux LAN client can use the same version and
an explicit CA and owner-only credential file (mode 0600):

```bash
andeiva firewall status --url https://<LAN-IP>:9443 \
  --ca-file ./ca.crt --credentials-file ./admin-a.json
```

Follow the [administrative guide](../../../internal/firewalladmin/docs/en.md) for
the shared request schema and Stage, Validate, Commit, Confirm, Save and Rollback.
Use the configured preview URL/paths rather than the disposable lab paths.
For real isolated traffic, run on the VM:

```bash
sudo /usr/lib/andeiva-preview/andeiva-preview probe --protocol tcp --port 18080
sudo /usr/lib/andeiva-preview/andeiva-preview probe --protocol udp --port 18080
```

Traffic observations are bounded samples per explicit rule, not connection logs.
API restart creates a new observation stream and invalidates login sessions.

## Recovery, update and remove

The optional native acceptance harness requires Bash and `jq` already installed
from verified offline Debian packages. Review the script and snapshot first:

```bash
sudo bash /usr/share/doc/andeiva-firewall-preview/tests/native.sh --ack-isolated-debian13-vm
```

Default execution only observes health, probes, resources and host invariance.
Add `--api-failure` to interrupt only the API, or `--lifecycle` to stop and start
the preview. Both options interrupt management. Reports are private, root-readable
under `/var/tmp`; they do not prove transaction parity or infer expected traffic
from a successful probe. Verify those separately against the intended revision.

API-only restart retains the helper deadline. Losing the helper closes the entire
preview. Stop the target, wait for all four service/socket units to be inactive,
then start it; do not assume `restart target` is an atomic replacement. A restart
in the same OS boot restores Running; a VM reboot selects saved Startup.
Uncertain journal state blocks rather than publishing an unverified revision.

A killed namespace daemon may leave a pinned namespace or runtime metadata.
Preserve evidence: the preview deliberately refuses automatic reclamation.
An authorized VM reboot clears volatile runtime resources; do not delete the
journal, runtime markers or namespace pins to bypass the recovery check.

Before updating, stop the target and create a protected backup of
`/etc/andeiva-preview` and `/var/lib/andeiva-preview`. Verify the new artifact and
install it with `dpkg -i`. Upgrade leaves the target stopped for review; it does
not regenerate identities or erase state. Start it explicitly after checking
compatibility. No automatic downgrade or signed appliance updater is provided.

```bash
sudo systemctl disable --now andeiva-preview.target
sudo dpkg --remove andeiva-firewall-preview
```

Removal retains configuration, credentials, journal and audit. Retirement and
secure destruction are separate explicit actions. Never include these files in
public Git or artifacts. Use `journalctl -u andeiva-preview-api.service` locally
for diagnostics and the generic health command for availability.

Audit segments and the transaction journal have finite budgets and fail closed
when exhausted; never truncate protected records to regain access. TLS expires
after the provisioned validity interval. Automatic certificate renewal, audit
archival, multi-interface runtime changes and the Local Service Policy Manager
are separate gates; configuration contracts do not imply those integrations work.
Native test results must be recorded separately before declaring this preview validated.
