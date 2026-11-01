import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
output = root / 'results/verification/rfc-m6-pilot-isolation-2026-10-30'
output.mkdir(parents=True, exist_ok=False)
cli = str(root / '.cache/m8-kube-tools/bin/docker')
env = {**os.environ, 'DOCKER_CONFIG': str(root / '.cache/pilot-linux-docker'),
       'DOCKER_HOST': 'unix:///tmp/kf8-01a12982-colima/kf8/docker.sock'}
commands = []

def docker(*args, check=True):
    result = subprocess.run([cli, *args], env=env, text=True, capture_output=True,
                            timeout=120, check=False)
    commands.append({'argv': ['docker', *args], 'exit_code': result.returncode})
    if check and result.returncode:
        raise RuntimeError(result.stderr)
    return result

manifest = json.loads((root / '.cache/pilot-linux-source.json').read_text())
def unchanged():
    return all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
               for name, digest in manifest.items())
assert unchanged()
(output / 'source.json').write_text(json.dumps(manifest, indent=2) + '\n')
shutil.copyfile(root / '.cache/pilot-linux-build-5.log', output / 'build.log')
shutil.copyfile(__file__, output / 'collect.py')
(output / 'revision.txt').write_text(subprocess.check_output(
    ['git', 'rev-parse', 'HEAD'], cwd=root, text=True))
summary = {'status': 'failed_linux_fixture', 'timestamp_utc': datetime.now(timezone.utc).isoformat(),
           'scope': 'Disposable Linux ARM64 container within the local test VM; no enterprise acceptance',
           'source_unchanged': False, 'commands': commands,
           'open_gates': ['Linux AMD64 CI execution', 'approved identity providers and deployed custody',
                          'independent writer/storage/restore/retention/SLO and owner acceptance']}
container = None
try:
    (output / 'image.json').write_text(docker('image', 'inspect', 'kf-pilot-isolation:20261030').stdout)
    (output / 'docker-version.json').write_text(docker('version', '--format', '{{json .}}').stdout)
    name = 'kf-pilot-isolation-20261030-' + os.urandom(4).hex()
    container = docker('create', '--name', name, '--network', 'none', '--pids-limit', '256',
                       '--memory', '1g', '--label', 'org.openkedge.fixture=pilot-isolation',
                       'kf-pilot-isolation:20261030').stdout.strip()
    for filename in ('source-sha256.txt', 'source.tar.gz', 'packages.txt', 'tools.txt'):
        docker('cp', container + ':/opt/kf/' + filename, str(output / filename))
    run = docker('start', '--attach', container, check=False)
    (output / 'report.json').write_text(run.stdout)
    (output / 'fixture.log').write_text(run.stderr)
    state = json.loads(docker('inspect', container).stdout)[0]
    (output / 'container.json').write_text(json.dumps(state, indent=2) + '\n')
    assert state['State']['ExitCode'] == 0 and not state['State']['OOMKilled'], state['State']
    host = state['HostConfig']
    assert host['NetworkMode'] == 'none' and not host['Privileged'] and not state['Mounts']
    assert not host['PortBindings'] and host['Memory'] == 1073741824 and host['PidsLimit'] == 256
    report = json.loads(run.stdout)
    assert report['status'] == 'passed' and len(report['live_queries']) == 5
    assert len(set(report['uids'].values())) == 4 and 0 not in report['uids'].values()
    pinned = {}
    for line in (output / 'source-sha256.txt').read_text().splitlines():
        digest, filename = line.split('  ', 1)
        pinned[filename] = digest
    assert pinned == manifest
    with tempfile.TemporaryDirectory(prefix='kf-pilot-cleanup-') as private:
        remaining = {}
        for filename in ('passwd', 'group'):
            destination = Path(private) / filename
            docker('cp', container + ':/etc/' + filename, str(destination))
            remaining[filename] = len(re.findall(r'^kf_[0-9a-f]{8}_(?:db|target|agent|recovery):',
                                                 destination.read_text(), re.MULTILINE))
        assert not any(remaining.values()), remaining
    summary.update(status='passed_linux_fixture', source_unchanged=unchanged(),
                   passed_groups=report['passed'], live_queries=len(report['live_queries']),
                   cleanup_remaining_accounts=remaining, binary_sha256=report['binary_sha256'])
    assert summary['source_unchanged']
except BaseException as error:
    summary['error'] = str(error)
    raise
finally:
    if container:
        removed = docker('rm', '-f', container, check=False)
        summary['container_removed'] = removed.returncode == 0
        if not summary['container_removed']:
            summary['status'] = 'failed_container_cleanup'
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'commands'}, indent=2))
