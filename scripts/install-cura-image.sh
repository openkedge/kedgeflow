#!/bin/bash
# Disposable approved image builder only. No service enrollment or signing keys.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "$(uname -m)" = aarch64
test "$(. /etc/os-release; echo "$VERSION_ID")" = 24.04
input_root=$(readlink -f "${1:?verified input directory required}")
test "$input_root" = /opt/kedgeflow/image-inputs
build_root=/var/lib/kedgeflow-image-build
mkdir -p "$build_root" /opt/kedgeflow/runtime

python3 - "$input_root" <<'PY'
import hashlib,json,re,sys
from pathlib import Path
p=Path(sys.argv[1]);m=json.loads((p/'inputs.json').read_text())
for entry in m:
    if not re.fullmatch(r'[A-Za-z0-9._-]+',entry['name']):raise RuntimeError('invalid input name')
    f=p/entry['name']
    assert f.is_file() and not f.is_symlink()
    assert hashlib.sha256(f.read_bytes()).hexdigest()==entry['sha256'],entry['name']
assert {e['name'] for e in m}>={'kedgeflow-core.tar.gz','node-v25.2.1-linux-arm64.tar.xz','keycloak-26.8.1.tar.gz','postgresql-18.3.tar.bz2','etcd-v3.6.5-linux-arm64.tar.gz','spire-1.15.5-linux-arm64-musl.tar.gz','amazon-ssm-agent.deb','amazon-ssm-agent.deb.sig','amazon-ssm-agent.gpg','pilot-source.tar.gz'}
PY

if [ "${2:-}" != --resume-postflight ]; then
export DEBIAN_FRONTEND=noninteractive
packages=(ca-certificates curl jq python3 python3-cryptography python3-venv
          openjdk-21-jre-headless openssl build-essential flex bison libatomic1
          pkg-config gnupg xz-utils bzip2 python3-boto3)
# Rebuild from the previously reviewed lock. Candidate resolution is an explicit
# first-bootstrap operation, never the default for a subsequent image build.
apt-get -o DPkg::Lock::Timeout=120 update > "$build_root/apt-update.log" 2>&1
locked=()
if test -f "$input_root/apt-package-lock.txt"; then
    python3 - "$input_root/apt-package-lock.txt" "${packages[@]}" <<'PY_LOCK'
import re,sys
from pathlib import Path
rows=Path(sys.argv[1]).read_text().splitlines()
assert len(rows)==len(sys.argv[2:])
assert all(re.fullmatch(r'[a-z0-9+.-]+=[A-Za-z0-9.+:~_-]+',row) for row in rows)
assert {row.split('=',1)[0] for row in rows}==set(sys.argv[2:])
PY_LOCK
    mapfile -t locked < "$input_root/apt-package-lock.txt"
elif [ "${2:-}" = --resolve-package-lock ]; then
    for package in "${packages[@]}"; do
        version=$(apt-cache policy "$package" | awk '/Candidate:/ && !seen {print $2; seen=1}')
        test -n "$version" && test "$version" != '(none)'
        locked+=("$package=$version")
    done
else
    echo 'verified apt-package-lock.txt required; initial resolution needs --resolve-package-lock' >&2
    exit 2
fi
printf '%s\n' "${locked[@]}" > "$build_root/apt-requested-versions.txt"
apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends "${locked[@]}" \
    > "$build_root/apt-install.log" 2>&1

mkdir -m 0700 -p "$build_root/gnupg"
fingerprint=$(gpg --homedir "$build_root/gnupg" --batch --with-colons \
    --import-options show-only --import "$input_root/amazon-ssm-agent.gpg" \
    2> "$build_root/ssm-signer.log" | awk -F: '$1=="fpr" && !seen {print $10; seen=1}')
test "$fingerprint" = 1C5B395CBE5E74E2F1CA21592784DBF388D19D46
gpg --homedir "$build_root/gnupg" --batch --import "$input_root/amazon-ssm-agent.gpg" \
    >> "$build_root/ssm-signer.log" 2>&1
gpg --homedir "$build_root/gnupg" --batch --verify \
    "$input_root/amazon-ssm-agent.deb.sig" "$input_root/amazon-ssm-agent.deb" \
    > "$build_root/ssm-signature.log" 2>&1

source_root=/opt/kedgeflow/pilot-source
mkdir -p "$source_root"
tar -xzf "$input_root/pilot-source.tar.gz" -C "$source_root" --no-same-owner
python3 "$source_root/scripts/verify-linux-package.py" "$input_root/kedgeflow-core.tar.gz" \
    > "$build_root/core-verification.json"
release=$(python3 - "$build_root/core-verification.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]));print(j['name'])
PY
)
mkdir -p "/opt/kedgeflow/releases/$release"
tar -xzf "$input_root/kedgeflow-core.tar.gz" -C "/opt/kedgeflow/releases/$release" \
    --strip-components=1 --no-same-owner
ln -s "/opt/kedgeflow/releases/$release" /opt/kedgeflow/current

for component in node etcd spire keycloak; do mkdir -p "/opt/kedgeflow/runtime/$component"; done
tar -xJf "$input_root/node-v25.2.1-linux-arm64.tar.xz" -C /opt/kedgeflow/runtime/node --strip-components=1 --no-same-owner
tar -xzf "$input_root/etcd-v3.6.5-linux-arm64.tar.gz" -C /opt/kedgeflow/runtime/etcd --strip-components=1 --no-same-owner
tar -xzf "$input_root/spire-1.15.5-linux-arm64-musl.tar.gz" -C /opt/kedgeflow/runtime/spire --strip-components=1 --no-same-owner
tar -xzf "$input_root/keycloak-26.8.1.tar.gz" -C /opt/kedgeflow/runtime/keycloak --strip-components=1 --no-same-owner
export PATH=/opt/kedgeflow/runtime/node/bin:/opt/kedgeflow/runtime/etcd:/opt/kedgeflow/runtime/spire/bin:$PATH
test "$(node --version)" = v25.2.1
etcd --version > "$build_root/etcd-version.txt"
spire-server --version > "$build_root/spire-version.txt" 2>&1
/opt/kedgeflow/runtime/keycloak/bin/kc.sh build --db=postgres --health-enabled=true \
    --metrics-enabled=true > "$build_root/keycloak-build.log" 2>&1

mkdir "$build_root/postgres"
tar -xjf "$input_root/postgresql-18.3.tar.bz2" -C "$build_root/postgres" --strip-components=1 --no-same-owner
(
    cd "$build_root/postgres"
    ./configure --prefix=/opt/kedgeflow/runtime/postgres --without-icu --without-readline --without-zlib
    make -j2
    make install
) > "$build_root/postgres-build.log" 2>&1
test "$(/opt/kedgeflow/runtime/postgres/bin/postgres --version)" = 'postgres (PostgreSQL) 18.3'
npm ci --prefix "$source_root/tests/sdk" --ignore-scripts --omit=dev \
    > "$build_root/npm-install.log" 2>&1

systemd-sysusers /opt/kedgeflow/current/share/sysusers.d/kedgeflow.conf
systemd-sysusers /opt/kedgeflow/current/share/pilot/cura/accounts/sysusers.conf
cat > /opt/kedgeflow/runtime/provider-sysusers.conf <<'CURA_USERS'
u kf-postgres - "Cura guarded SQL database" /nonexistent /usr/sbin/nologin
u kf-identity-db - "Cura identity provider database" /nonexistent /usr/sbin/nologin
u kf-keycloak - "Cura Keycloak provider" /nonexistent /usr/sbin/nologin
u kf-spire-server - "Cura SPIRE server" /nonexistent /usr/sbin/nologin
u kf-spire-agent - "Cura SPIRE node attestor" /nonexistent /usr/sbin/nologin
u kf-etcd - "Cura authority ledger" /nonexistent /usr/sbin/nologin
u kf-witness - "Cura separate restore witness" /nonexistent /usr/sbin/nologin
u kf-observer - "Cura read-only evidence observer" /nonexistent /usr/sbin/nologin
u kf-monitor - "Cura read-only monitor" /nonexistent /usr/sbin/nologin
u kf-agent - "Cura untrusted AI workflow" /nonexistent /usr/sbin/nologin
CURA_USERS
systemd-sysusers /opt/kedgeflow/runtime/provider-sysusers.conf
systemd-tmpfiles --create /opt/kedgeflow/current/share/tmpfiles.d/kedgeflow.conf
systemd-tmpfiles --create /opt/kedgeflow/current/share/pilot/cura/accounts/tmpfiles.conf
# Install selected units disabled, with no credentials/configuration or authority.
for unit in /opt/kedgeflow/current/share/systemd/*; do
    case "$(basename "$unit")" in kedgeflow-control.service|kedgeflow.target) continue ;; esac
    install -m0644 "$unit" /etc/systemd/system/
done
install -m0644 /opt/kedgeflow/current/share/pilot/cura/systemd/* /etc/systemd/system/
systemctl mask kedgeflow-control.service kedgeflow.target
systemctl daemon-reload
if systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket; then
    echo 'SSH must be inactive before image capture' >&2
    exit 1
fi
fi

# The installer uses a private umask for evidence. Public executable ancestors
# must still be traversable by the separate non-root runtime identities.
chmod 0755 /opt/kedgeflow
chmod -R go+rX /opt/kedgeflow/runtime /opt/kedgeflow/releases /opt/kedgeflow/pilot-source
test "$(/opt/kedgeflow/runtime/postgres/bin/postgres --version)" = 'postgres (PostgreSQL) 18.3'
test "$(/opt/kedgeflow/runtime/node/bin/node --version)" = v25.2.1
runuser -u kf-postgres -- /opt/kedgeflow/runtime/postgres/bin/postgres --version
runuser -u kf-agent -- /opt/kedgeflow/runtime/node/bin/node --version
runuser -u kf-etcd -- /opt/kedgeflow/runtime/etcd/etcd --version
runuser -u kf-spire-server -- /opt/kedgeflow/runtime/spire/bin/spire-server --version
for binary in /opt/kedgeflow/current/bin/*; do
    if [ "$(basename "$binary")" = kf-ledger-credentials ]; then
        runuser -u kf-agent -- "$binary" --help
    else
        runuser -u kf-agent -- "$binary" --version
    fi
done > "$build_root/native-versions.txt"
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' > "$build_root/dpkg-inventory.tsv"
dpkg-deb -f "$input_root/amazon-ssm-agent.deb" Version > "$build_root/ssm-version.txt"

python3 - "$input_root" "$build_root" <<'PY'
import json,hashlib,sys,subprocess
from pathlib import Path
inputs,build=map(Path,sys.argv[1:]);report={
 'format':'kedgeflow-cura-image-build-v1','status':'installed_unenrolled',
 'native_source_commit':'4876d119c3f0d0de785b37d98d1a41c9b8db0eac',
 'bundle_sha256':hashlib.sha256((inputs/'kedgeflow-core.tar.gz').read_bytes()).hexdigest(),
 'inputs':json.loads((inputs/'inputs.json').read_text()),
 'apt_requested_versions':(build/'apt-requested-versions.txt').read_text().splitlines(),
 'dpkg_inventory_sha256':hashlib.sha256((build/'dpkg-inventory.tsv').read_bytes()).hexdigest(),
 'native_versions_sha256':hashlib.sha256((build/'native-versions.txt').read_bytes()).hexdigest(),
 'public_executable_traversal_verified':True,
 'ssm_signer_fingerprint':'1C5B395CBE5E74E2F1CA21592784DBF388D19D46',
 'ssm_version':(build/'ssm-version.txt').read_text().strip(),
 'ssh_disabled':True,'runtime_services_enabled':False,'runtime_keys_generated':False,
 'production_qualified':False,'execution_authority':False}
Path('/opt/kedgeflow/IMAGE-MANIFEST.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'manifest_sha256':hashlib.sha256(Path('/opt/kedgeflow/IMAGE-MANIFEST.json').read_bytes()).hexdigest()}))
PY
