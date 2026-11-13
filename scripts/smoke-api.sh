#!/usr/bin/env bash
set -euo pipefail
mkdir -p bin
go build -trimpath -buildvcs=false -o bin/andeiva ./cmd/andeiva
go build -trimpath -buildvcs=false -o bin/andeiva-api ./cmd/andeiva-api
export ANDEIVA_LISTEN_ADDR=127.0.0.1:44000
bin/andeiva-api &
api_pid=$!
cleanup() {
  if kill -0 "$api_pid" 2>/dev/null; then
    kill -TERM "$api_pid"
    wait "$api_pid" || true
  fi
}
trap cleanup EXIT
ready=false
for attempt in {1..30}; do
  kill -0 "$api_pid"
  if bin/andeiva-api --healthcheck 2>/dev/null; then
    ready=true
    break
  fi
  sleep 0.1
done
test "$ready" = true
test "$(curl --fail --silent --max-time 2 http://127.0.0.1:44000/healthz)" = '{"status":"ok"}'
test "$(curl --silent --max-time 2 --output /dev/null --write-out '%{http_code}' http://127.0.0.1:44000/api/config)" = 404
bin/andeiva --lang en status
bin/andeiva --lang es status
bin/andeiva --lang pt status
for locale in en es pt; do
  # Configuration help is implemented; administrative operations still need
  # explicit verified transport and credentials, even for readback.
  bin/andeiva --lang "$locale" configuration help >/dev/null
  bin/andeiva --lang "$locale" config >/dev/null
  for operation in status commit; do
    status=0
    bin/andeiva --lang "$locale" configuration "$operation" >/dev/null 2>&1 || status=$?
    if [[ $status != 2 ]]; then
      printf 'Configuration %s without credentials returned %s, expected 2\n' "$operation" "$status" >&2
      exit 1
    fi
  done
done
printf 'Process sample (not an appliance benchmark):\n'
ps -p "$api_pid" -o rss=,pcpu=,etime=
kill -TERM "$api_pid"
wait "$api_pid"
trap - EXIT
printf 'Native API/CLI smoke and SIGTERM shutdown passed.\n'
