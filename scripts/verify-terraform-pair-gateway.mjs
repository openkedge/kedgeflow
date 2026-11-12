#!/usr/bin/env node
// Read-only replay of locally generated gateway evidence; no execution authority.
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyCase } from './verify-terraform-pair.mjs';
export async function verify(root) {
  return { status: 'PASS', scope: 'local gateway/SDK evidence replay; no independent attestation', cases: await Promise.all(['normal', 'lost', 'partial', 'partial-lost'].map(name => verifyCase(root, name, { gateway: true }))) };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) console.log(JSON.stringify(await verify(resolve(process.argv[2])), null, 2));
