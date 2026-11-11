#!/usr/bin/env bash
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$source_dir"
go test -race -count=1 ./check
go vet ./check
bash -n build.sh install.sh install-in-namespace.sh capture.sh tests/run.sh tests/signature-native.sh tests/apt-terminal-log.sh tests/build-baseline.sh
shellcheck build.sh install.sh install-in-namespace.sh capture.sh tests/run.sh tests/signature-native.sh tests/apt-terminal-log.sh tests/build-baseline.sh
python3 tests/installer_fixture.py -v
