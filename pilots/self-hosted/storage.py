"""Root-only quiescence for the disposable SPIRE provider storage fixture."""

import json
import os
import shutil
import signal
import sqlite3
import sys
import time
from pathlib import Path


def active_spire():
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            name = (entry / 'comm').read_text().strip()
            state = (entry / 'stat').read_text().rsplit(')', 1)[1].split()[0]
            if name in ('spire-agent', 'spire-server') and state != 'Z':
                found.append(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return found


def stop():
    pids = active_spire()
    if len(pids) != 2:
        raise RuntimeError('cold backup requires the running fixture server and agent')
    for pid in pids:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 15
    while active_spire():
        if time.monotonic() >= deadline:
            raise RuntimeError('SPIRE did not quiesce; backup refused')
        time.sleep(0.05)
    uri = 'file:/var/lib/spire/server/datastore.sqlite3?mode=ro'
    with sqlite3.connect(uri, uri=True) as database:
        if database.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise RuntimeError('SPIRE datastore integrity check failed')
    json.loads(Path('/var/lib/spire/server/keys.json').read_text())
    print(json.dumps({'status': 'quiesced', 'processes_stopped': len(pids),
                      'datastore_integrity': 'ok'}))


def reset_agent():
    if any(Path(f'/proc/{pid}/comm').read_text().strip() == 'spire-agent'
           for pid in active_spire()):
        raise RuntimeError('agent reset requires a stopped agent')
    # Agent keys use memory storage. Reattest freshly; only server storage is restored.
    root = Path('/var/lib/spire/agent')
    shutil.rmtree(root)
    root.mkdir(mode=0o700)
    Path('/run/kf-spire/agent.sock').unlink(missing_ok=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['stop']:
        stop()
    elif sys.argv[1:] == ['reset-agent']:
        reset_agent()
    else:
        raise SystemExit('expected stop or reset-agent')
