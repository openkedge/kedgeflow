#!/usr/bin/env bash
# Disposable three-member loopback etcd for Rust integration tests.
set -euo pipefail

etcd_version=3.6.5
etcd_binary=${ETCD_BINARY:-etcd}
if ! command -v "$etcd_binary" >/dev/null 2>&1; then
  printf 'Set ETCD_BINARY to an etcd %s executable.\n' "$etcd_version" >&2
  exit 1
fi
actual_version=$("$etcd_binary" --version | sed -n 's/^etcd Version: //p')
if [[ "$actual_version" != "$etcd_version" ]]; then
  printf 'Expected etcd %s, received %s.\n' "$etcd_version" "$actual_version" >&2
  exit 1
fi
command -v curl >/dev/null 2>&1 || { printf 'curl is required.\n' >&2; exit 1; }

IFS=, read -r -a client_ports <<< "${KF_ETCD_CLIENT_PORTS:-12379,22379,32379}"
IFS=, read -r -a peer_ports <<< "${KF_ETCD_PEER_PORTS:-12380,22380,32380}"
if [[ ${#client_ports[@]} != 3 || ${#peer_ports[@]} != 3 ]]; then
  printf 'Client and peer port lists must each contain three ports.\n' >&2
  exit 1
fi
all_ports=()
for port in "${client_ports[@]}" "${peer_ports[@]}"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( 10#$port < 1024 || 10#$port > 65535 )); then
    printf 'Test ports must be integers from 1024 through 65535.\n' >&2
    exit 1
  fi
  # Bash 3.2 (the macOS system shell) treats an empty array as unset under -u.
  for existing in "${all_ports[@]-}"; do
    if [[ "$port" == "$existing" ]]; then
      printf 'All six test ports must be distinct.\n' >&2
      exit 1
    fi
  done
  all_ports+=("$port")
done

data_dir=$(mktemp -d "${TMPDIR:-/tmp}/kedgeflow-etcd.XXXXXX")
pids=()
cleanup() {
  trap - EXIT INT TERM
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  rm -rf -- "$data_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cluster="node0=http://127.0.0.1:${peer_ports[0]},node1=http://127.0.0.1:${peer_ports[1]},node2=http://127.0.0.1:${peer_ports[2]}"
endpoints=()
for member in 0 1 2; do
  endpoint="http://127.0.0.1:${client_ports[$member]}"
  peer="http://127.0.0.1:${peer_ports[$member]}"
  endpoints+=("$endpoint")
  "$etcd_binary" \
    --name="node$member" --data-dir="$data_dir/node$member" \
    --listen-client-urls="$endpoint" --advertise-client-urls="$endpoint" \
    --listen-peer-urls="$peer" --initial-advertise-peer-urls="$peer" \
    --initial-cluster="$cluster" --initial-cluster-state=new \
    --initial-cluster-token="kedgeflow-test-$$" \
    --enable-grpc-gateway=true --log-level=error \
    >"$data_dir/node$member.log" 2>&1 &
  pids+=("$!")
done

deadline=$((SECONDS + 30))
while :; do
  healthy=1
  for member in 0 1 2; do
    if ! kill -0 "${pids[$member]}" 2>/dev/null; then
      cat "$data_dir/node$member.log" >&2
      printf 'etcd member %s exited before readiness.\n' "$member" >&2
      exit 1
    fi
    if ! curl --fail --silent --max-time 1 "${endpoints[$member]}/health" >/dev/null; then
      healthy=0
    fi
  done
  if (( healthy )); then break; fi
  if (( SECONDS >= deadline )); then
    cat "$data_dir"/node*.log >&2
    printf 'Three-member etcd readiness timed out.\n' >&2
    exit 1
  fi
  sleep 0.2
done

export ETCD_ENDPOINT=${endpoints[0]}
export ETCD_ENDPOINTS="${endpoints[0]},${endpoints[1]},${endpoints[2]}"
export KF_REQUIRE_ETCD=1
printf 'etcd=%s members=3 topology=single-host-loopback\n' "$etcd_version"
printf 'ETCD_ENDPOINT=%s\nETCD_ENDPOINTS=%s\nKF_REQUIRE_ETCD=1\n' "$ETCD_ENDPOINT" "$ETCD_ENDPOINTS"
if [[ ${1:-} == -- ]]; then shift; fi
if (( $# )); then
  "$@"
else
  printf 'Cluster retained in %s until interrupted.\n' "$data_dir"
  wait
fi
