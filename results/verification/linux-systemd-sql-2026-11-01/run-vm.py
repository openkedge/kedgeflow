import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

root = Path.cwd()
base = ['ssh', '-F', '/tmp/kf8-01a12982-lima/colima-kfmlp20261101/ssh.config', 'lima-colima-kfmlp20261101']
package = root / 'dist/linux-readiness-final/kedgeflow-core-0.9.0-alpha.1-linux-aarch64-22c3fbfe206bc010.tar.gz'
expected = '59dac3a300e0c1ece9294b9f8bc128a005bcbaf0c98c2c3e73a73489706c15f5'
assert hashlib.sha256(package.read_bytes()).hexdigest() == expected

def run(args, **kw):
    return subprocess.run(base + args, capture_output=True, timeout=240, check=False, **kw)

made = run(['mktemp', '-d', '/tmp/kf-live-sql.XXXXXX'])
assert made.returncode == 0, made.stderr
source = made.stdout.decode().strip()
assert Path(source).parent == Path('/tmp') and Path(source).name.startswith('kf-live-sql.')
try:
    data = io.BytesIO()
    names = ['scripts/qualify-systemd-sql.py', 'scripts/qualify-postgres-isolation.py', 'scripts/linux-sql-workflow.py', 'scripts/package-linux.py', 'scripts/verify-linux-package.py', 'config/postgres-target.example.json', 'migrations/postgres/0001-reservation.sql', 'fixtures/grant.json']
    with tarfile.open(fileobj=data, mode='w') as archive:
        for name in names:
            archive.add(root / name, arcname=name)
        archive.add(root / '.cache/linux-sql-runtime/postgres', arcname='postgres')
        archive.add(package, arcname='bundle.tar.gz')
    copied = run(['tar', '-xf', '-', '-C', source], input=data.getvalue())
    assert copied.returncode == 0, copied.stderr
    result = run(['sudo', '/usr/bin/python3', source + '/scripts/qualify-systemd-sql.py', '--ephemeral-host', '--package', source + '/bundle.tar.gz', '--sha256', expected, '--bindir', source + '/postgres/bin'])
    (root / '.cache/linux-systemd-sql.json').write_bytes(result.stdout)
    (root / '.cache/linux-systemd-sql.stderr').write_bytes(result.stderr)
    print('exit_code', result.returncode)
    print(result.stderr.decode()[-6000:])
    if result.returncode == 0:
        report = json.loads(result.stdout)
        print(json.dumps({k:v for k,v in report.items() if k != 'live_queries'}, indent=2))
        print('live_events', len(report['live_queries'][-1]['events']))
    assert result.returncode == 0
finally:
    removed = run(['rm', '-r', source])
    assert removed.returncode == 0, removed.stderr
    print('source_copy_removed', True)
