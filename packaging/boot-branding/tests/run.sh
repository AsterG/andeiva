#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C TZ=UTC
(( EUID != 0 )) || { printf '%s\n' ANDEIVA_TEST_REQUIRES_NONROOT >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
test_root=$(mktemp -d /tmp/andeiva-boot-tests.XXXXXXXX)
cleanup() { case "$test_root" in /tmp/andeiva-boot-tests.*) rm -rf -- "$test_root" ;; *) exit 1 ;; esac; }
trap cleanup EXIT
export GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off
bash -n "$source_dir/build.sh" "$source_dir/tests/run.sh"
(cd "$source_dir/render" && go test -race . && go vet .)
python3 "$source_dir/tests/grub_layout.py"
for build in first second; do
  bash "$source_dir/build.sh" '0.1.0~alpha901' "$test_root/$build" 1794355200
  python3 "$source_dir/tests/check-package.py" "$test_root/$build/andeiva-boot-branding_0.1.0~alpha901_all.deb"
done
cmp "$test_root/first/andeiva-boot-branding_0.1.0~alpha901_all.deb" "$test_root/second/andeiva-boot-branding_0.1.0~alpha901_all.deb"
if bash "$source_dir/build.sh" '0.1.0;false' "$test_root/invalid" 1794355200; then exit 1; fi
[[ ! -e "$test_root/invalid" ]]
if bash "$source_dir/build.sh" '0.1.0~alpha901' "$test_root/first" 1794355200; then exit 1; fi
# Mutation checks do not install or execute the candidate packages.
for mutation in hook logo grub-copy path oversize conflicts duplicate; do
  candidate="$test_root/$mutation"
  dpkg-deb -R "$test_root/first/andeiva-boot-branding_0.1.0~alpha901_all.deb" "$candidate"
  if [[ "$mutation" = hook ]]; then
    printf '#!/bin/sh\nexit 0\n' > "$candidate/DEBIAN/postinst"
    chmod 0755 "$candidate/DEBIAN/postinst"
  elif [[ "$mutation" = logo ]]; then
    printf invalid > "$candidate/usr/share/plymouth/themes/andeiva/andeiva-logo.png"
  elif [[ "$mutation" = grub-copy ]]; then
    cp "$candidate/usr/share/grub/themes/andeiva/andeiva-logo.png" "$candidate/usr/share/grub/themes/andeiva/andeiva-grub-logo.png"
  elif [[ "$mutation" = path ]]; then
    mkdir -p "$candidate/etc/andeiva-boot-unexpected"
  elif [[ "$mutation" = oversize ]]; then
    dd if=/dev/zero of="$candidate/oversize" bs=1048576 count=4 status=none
  elif [[ "$mutation" = conflicts ]]; then
    printf 'Conflicts: systemd\n' >> "$candidate/DEBIAN/control"
  else
    head -n 1 "$candidate/DEBIAN/md5sums" > "$test_root/duplicate-line"
    tail -n +3 "$candidate/DEBIAN/md5sums" > "$test_root/other-lines"
    cat "$test_root/duplicate-line" "$test_root/duplicate-line" "$test_root/other-lines" > "$candidate/DEBIAN/md5sums"
  fi
  dpkg-deb --root-owner-group --build "$candidate" "$test_root/$mutation.deb" >/dev/null
  if python3 "$source_dir/tests/check-package.py" "$test_root/$mutation.deb" > "$test_root/$mutation.result" 2>&1; then exit 1; fi
  case "$mutation" in
    hook) grep -qx ANDEIVA_BOOT_PACKAGE_ACTIVE_CONTENT "$test_root/$mutation.result" ;;
    logo) grep -qx ANDEIVA_BOOT_LOGO_INTEGRITY "$test_root/$mutation.result" ;;
    grub-copy) grep -qx ANDEIVA_BOOT_GRUB_COPY_INTEGRITY "$test_root/$mutation.result" ;;
    path) grep -qx ANDEIVA_BOOT_PACKAGE_PATH "$test_root/$mutation.result" ;;
    oversize) grep -qx ANDEIVA_BOOT_ARCHIVE_SIZE "$test_root/$mutation.result" ;;
    conflicts) grep -qx ANDEIVA_BOOT_PACKAGE_CONTROL "$test_root/$mutation.result" ;;
    duplicate) grep -qx ANDEIVA_BOOT_PACKAGE_CHECKSUM "$test_root/$mutation.result" ;;
  esac
done
concurrent_build() {
  set +e
  bash "$source_dir/build.sh" '0.1.0~alpha901' "$test_root/concurrent" 1794355200 > "$test_root/concurrent-$1.log" 2>&1
  printf '%s\n' "$?" > "$test_root/concurrent-$1.exit"
}
concurrent_build first &
first_pid=$!
concurrent_build second &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
first_result=$(cat "$test_root/concurrent-first.exit")
second_result=$(cat "$test_root/concurrent-second.exit")
[[ "$first_result:$second_result" = 0:1 || "$first_result:$second_result" = 1:0 ]]
grep -Exq 'ANDEIVA_BOOT_OUTPUT_BUSY|ANDEIVA_BOOT_OUTPUT_EXISTS' "$test_root"/concurrent-*.log
cmp "$test_root/first/andeiva-boot-branding_0.1.0~alpha901_all.deb" "$test_root/concurrent/andeiva-boot-branding_0.1.0~alpha901_all.deb"
python3 "$source_dir/tests/check-package.py" "$test_root/concurrent/andeiva-boot-branding_0.1.0~alpha901_all.deb"
printf '%s\n' ANDEIVA_BOOT_UNPRIVILEGED_TESTS_OK
