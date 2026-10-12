import { mkdir, open, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonical, hash, strictJson } from './records.mjs';

// One owner per operation. A crashed owner's lock is retained for explicit
// operational recovery; elapsed time never proves that dispatch did not happen.
export class FileOperationStore {
  constructor(directory) { this.directory = directory; }
  path(qid) {
    if (typeof qid !== 'string' || !qid || qid.length > 1024) throw new Error('operation identity required');
    return join(this.directory, `${hash(qid).toString('hex')}.json`);
  }
  async get(qid) {
    try {
      const f = await open(this.path(qid), 'r');
      try {
        const stat = await f.stat();
        if (!stat.isFile() || stat.size > 1 << 20) throw new Error('operation record exceeds bound');
        return strictJson(await f.readFile('utf8'));
      } finally { await f.close(); }
    }
    catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  }
  async put(qid, value) {
    const raw = canonical(value);
    if (Buffer.byteLength(raw) > 1 << 20) throw new Error('operation record exceeds bound');
    const path = this.path(qid); const temp = `${path}.${randomUUID()}.tmp`;
    const f = await open(temp, 'wx', 0o600);
    try { await f.writeFile(raw); await f.sync(); } finally { await f.close(); }
    try { await rename(temp, path); } finally { await unlink(temp).catch(() => {}); }
    const dir = await open(this.directory, 'r'); try { await dir.sync(); } finally { await dir.close(); }
  }
  async withLock(qid, callback) {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const path = `${this.path(qid)}.lock`;
    const lock = await open(path, 'wx', 0o600);
    try { return await callback(); }
    finally { await lock.close(); await unlink(path); }
  }
}
