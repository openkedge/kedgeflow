#!/bin/bash
# Run in an independent systemd job on the disposable builder, after build success.
# Purges only builder management identity; refuses any enrolled runtime material.
set -euo pipefail
umask 077
test "$(id -u)" = 0
test "${1:-}" = --ephemeral-image-builder
expected_instance=${2:?exact builder instance required}
report_bucket=${3:?approved artifact bucket required}
case "$expected_instance" in i-[a-f0-9]*) ;; *) exit 2 ;; esac
case "$report_bucket" in kedgeflow-cura-*-artifacts-*) ;; *) exit 2 ;; esac
test -f /opt/kedgeflow/IMAGE-MANIFEST.json
test ! -e /var/lib/kedgeflow/pilot

python3 - "$expected_instance" <<'PY'
import json,sys,urllib.request
from pathlib import Path
token=urllib.request.urlopen(urllib.request.Request(
 'http://169.254.169.254/latest/api/token',method='PUT',
 headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'}),timeout=5).read().decode()
instance=urllib.request.urlopen(urllib.request.Request(
 'http://169.254.169.254/latest/meta-data/instance-id',
 headers={'X-aws-ec2-metadata-token':token}),timeout=5).read().decode()
assert instance==sys.argv[1]
report=json.loads(Path('/opt/kedgeflow/IMAGE-MANIFEST.json').read_text())
assert report['status']=='installed_unenrolled'
assert report['public_executable_traversal_verified'] is True
assert report['execution_authority'] is False and report['runtime_keys_generated'] is False
assert not any(p.is_file() for p in Path('/etc/kedgeflow').rglob('*'))
assert not Path('/root/.aws/credentials').exists()
PY

materials=/opt/kedgeflow/BUILD-MATERIALS
build_root=/var/lib/kedgeflow-image-build
mkdir -p "$materials"
for name in apt-requested-versions.txt dpkg-inventory.tsv ssm-signature.log ssm-signer.log \
            ssm-version.txt core-verification.json native-versions.txt etcd-version.txt \
            spire-version.txt; do
    install -m0644 "$build_root/$name" "$materials/$name"
done
if test -s "$build_root/nonroot-versions.txt"; then
    install -m0644 "$build_root/nonroot-versions.txt" "$materials/nonroot-versions.txt"
fi
install -m0644 /opt/kedgeflow/image-inputs/inputs.json "$materials/inputs.json"
install -m0644 /opt/kedgeflow/image-inputs/amazon-ssm-agent.deb /opt/kedgeflow/ssm-agent.pinned.deb

# The fresh package must not register this builder identity before image capture.
mkdir -p /etc/systemd/system/amazon-ssm-agent.service.d
touch "$build_root/image-finalizing"
cat > /etc/systemd/system/amazon-ssm-agent.service.d/image-finalizing.conf <<'CURA_UNIT'
[Unit]
ConditionPathExists=!/var/lib/kedgeflow-image-build/image-finalizing
CURA_UNIT
systemctl daemon-reload
if snap list amazon-ssm-agent >/dev/null 2>&1; then
    snap remove --purge amazon-ssm-agent
fi
if dpkg-query -W -f='${Status}' amazon-ssm-agent 2>/dev/null | grep -q 'install ok installed'; then
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 purge -y amazon-ssm-agent
fi
# No agent is installed/running now. Remove only this builder's old registration
# and orchestration state before installing the verified fresh package.
if systemctl is-active --quiet amazon-ssm-agent.service; then exit 1; fi
if systemctl is-active --quiet snap.amazon-ssm-agent.amazon-ssm-agent.service; then exit 1; fi
rm -rf /var/lib/amazon/ssm /var/log/amazon/ssm
dpkg -i /opt/kedgeflow/ssm-agent.pinned.deb
systemctl daemon-reload
if systemctl is-active --quiet amazon-ssm-agent.service; then exit 1; fi
systemctl enable amazon-ssm-agent.service
test ! -e /var/lib/amazon/ssm/credentials
test ! -e /root/.aws/credentials
test -z "$(dpkg --audit)"

rm -f /etc/ssh/ssh_host_* /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem
cloud-init clean --logs --machine-id
python3 - "$expected_instance" "$report_bucket" <<'PY'
import hashlib,json,sys,boto3
from pathlib import Path
report={'format':'kedgeflow-cura-image-finalization-v1','builder_instance':sys.argv[1],
 'builder_registration_purged':True,'fresh_ssm_package_inactive':True,
 'shared_credentials_absent':True,'cloud_init_identity_reset':True,
 'runtime_services_enrolled':False,'runtime_keys_generated':False,
 'image_manifest_sha256':hashlib.sha256(Path('/opt/kedgeflow/IMAGE-MANIFEST.json').read_bytes()).hexdigest(),
 'production_qualified':False,'execution_authority':False}
raw=(json.dumps(report,indent=2)+'\n').encode()
Path('/opt/kedgeflow/IMAGE-SANITIZED.json').write_bytes(raw)
boto3.client('s3',region_name='us-west-2').put_object(
 Bucket=sys.argv[2],Key='build-reports/'+sys.argv[1]+'/image-finalization.json',Body=raw)
PY
rm -f /opt/kedgeflow/ssm-agent.pinned.deb
rm -rf /opt/kedgeflow/image-inputs /var/lib/kedgeflow-image-build/postgres
rm -f /var/lib/kedgeflow-image-inputs.tar
rm -f /etc/systemd/system/amazon-ssm-agent.service.d/image-finalizing.conf
rm -f "$build_root/image-finalizing"
systemctl daemon-reload
sync
shutdown -h now
