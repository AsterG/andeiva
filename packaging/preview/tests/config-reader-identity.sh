#!/usr/bin/env bash
set -euo pipefail
templates=$(cd -- "$(dirname -- "$0")/.." && pwd)
area=$(mktemp -d)
trap 'rm -rf -- "$area"' EXIT
mkdir "$area/bin"
# Run the maintainer script without root, host NSS changes or service control.
# Only this disposable filesystem maps the test user's ownership to root.
cat > "$area/bin/getent" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  group) file=$FIXTURE/groups;;
  passwd) file=$FIXTURE/passwd;;
  *) exit 2;;
esac
if (( $# == 1 )); then cat "$file"; else
  awk -F: -v name="$2" '$1==name {print; found=1} END {exit !found}' "$file"
fi
EOF
cat > "$area/bin/addgroup" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $* == '--system andeiva-config-reader' ]]
printf 'andeiva-config-reader:x:%s:\n' "${READER_GID:-62004}" >> "$FIXTURE/groups"
EOF
cat > "$area/bin/stat" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $1 == -c && $3 == "$FIXTURE/"* ]]
case "$2" in
  '%u:%a') /usr/bin/stat -c '0:%a' "$3";;
  '%u:%g:%a:%h') /usr/bin/stat -c '0:0:%a:%h' "$3";;
  *) exit 2;;
esac
EOF
cat > "$area/bin/install" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=()
while (( $# )); do
  case "$1" in -o|-g) [[ $2 == root ]]; shift 2;; *) args+=("$1"); shift;; esac
done
exec /usr/bin/install "${args[@]}"
EOF
cat > "$area/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
[[ $* == daemon-reload ]]
EOF
cat > "$area/bin/adduser" <<'EOF'
#!/bin/sh
exit 99
EOF
chmod 0755 "$area/bin/"*
export PATH="$area/bin:/usr/bin:/bin"
fixture() {
  export FIXTURE=$area/$1
  mkdir -m 0700 "$FIXTURE"
  mkdir -m 0700 "$FIXTURE/identity"
  printf 'andeiva-preview-api:x:62001:\nandeiva-preview-helper:x:62002:\nandeiva-preview-ipc:x:62003:\n' > "$FIXTURE/groups"
  printf 'andeiva-preview-api:x:62001:62001::/nonexistent:/usr/sbin/nologin\nandeiva-preview-helper:x:62002:62002::/nonexistent:/usr/sbin/nologin\n' > "$FIXTURE/passwd"
  printf 'andeiva-preview-api:62001:62001:/nonexistent:/usr/sbin/nologin\nandeiva-preview-helper:62002:62002:/nonexistent:/usr/sbin/nologin\nandeiva-preview-api:62001\nandeiva-preview-helper:62002\nandeiva-preview-ipc:62003\n' > "$FIXTURE/identity/identities"
  chmod 0600 "$FIXTURE/identity/identities"
  sed "s|^identity_dir=.*|identity_dir=$FIXTURE/identity|" "$templates/postinst" > "$FIXTURE/postinst"
}
run() { /bin/sh "$FIXTURE/postinst" configure > "$FIXTURE/result.log" 2>&1; }
refuse() { if run; then echo "FAIL: accepted $1" >&2; exit 1; fi; }
fixture idempotent
run
cp "$FIXTURE/identity/config-reader-v1" "$FIXTURE/original"
run
cmp "$FIXTURE/original" "$FIXTURE/identity/config-reader-v1"
[[ $(/usr/bin/stat -c '%a:%h' "$FIXTURE/identity/config-reader-v1") == 600:1 ]]
printf 'andeiva-config-reader:x:62004:intruder\n' > "$FIXTURE/extra"
sed -i '/^andeiva-config-reader:/d' "$FIXTURE/groups"
cat "$FIXTURE/extra" >> "$FIXTURE/groups"
refuse supplementary-member
fixture preexisting
printf 'andeiva-config-reader:x:62004:\n' >> "$FIXTURE/groups"
refuse unregistered-group
fixture reused-gid
export READER_GID=62001
refuse shared-gid
unset READER_GID
fixture primary-member
run
printf 'intruder:x:62010:62004::/nonexistent:/usr/sbin/nologin\n' >> "$FIXTURE/passwd"
refuse primary-member
fixture writable-record
run
chmod 0660 "$FIXTURE/identity/config-reader-v1"
refuse writable-record
fixture linked-record
run
ln "$FIXTURE/identity/config-reader-v1" "$FIXTURE/alias"
refuse linked-record
fixture changed-record
run
printf '{"version":1,"name":"andeiva-config-reader","gid":62005}\n' > "$FIXTURE/identity/config-reader-v1"
refuse changed-record
printf 'PASS: reader identity registration, idempotency and ownership/member/GID refusal; no host NSS or services changed\n'
