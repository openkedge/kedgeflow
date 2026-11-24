#!/usr/bin/env node
// Fixed-row evidence source and bounded relay. Neither process has SQL writer authority.
import { X509Certificate, verify } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createServer, request } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import { lstat, readFile, open, readdir, unlink } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { canonical, digest, exact, hash, privateSeed, publicBytes, publicKey, recordDigest,
  same, signedRecord, strictJson, verifyRecord } from '../sdk/node/records.mjs';
import { validateKeycloakToken } from '../sdk/node/identity-profile.mjs';
import { SQL_ACTION, SQL_SCHEMA } from '../sdk/node/sql-leaf.mjs';

const run = promisify(execFile);
const AGENT = 'spiffe://cura.kedgeflow.internal/agent';
const RELAY = 'spiffe://cura.kedgeflow.internal/evidence-relay';
const SQL_OBSERVER = 'spiffe://cura.kedgeflow.internal/sql-observer';
const EXTERNAL = 'https://services.cura.kedgeflow.internal:8444/evidence';
const UPSTREAM = 'https://sql.cura.kedgeflow.internal:8452/evidence';
const SCOPES = ['reservation:request', 'kf.admit', 'kf.issue', 'kf.status', 'kf.evidence'];
const MAX_BODY = 64 << 10;
const utf8 = bytes => new TextDecoder('utf-8',{fatal:true}).decode(bytes);
export const RESULT_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['version', 'reservation', 'active', 'satisfied'],
  properties: { version: {type:'string'}, reservation: {type:'string'},
    active: {type:'boolean'}, satisfied: {type:'boolean'} }
};
const label = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/.test(value);
const hex = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const b64 = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('encoding');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) throw Error('encoding');
  return bytes;
};

export function validateContract(c) {
  exact(c, ['profile','tenant','resource','subject','workload','proposalKeys','descriptorDigest',
    'policy','question','resultSchema','providerId','evidenceKeyId','manifestKeyId',
    'evidencePublicKey','manifestPublicKey',
    'authorizationKeyId','authorizationKey','dpopThumbprint','until']);
  exact(c.resource, ['id','incarnation']); exact(c.subject, ['iss','sub']);
  exact(c.policy, ['id','epoch','digest']); exact(c.question, ['id','schema','digest']);
  exact(c.resultSchema, ['id','schema','digest']);
  if (c.profile !== 'kedgeflow-cura-sql-observer-v1' || c.tenant !== 'cura-pilot' ||
      c.resource.id !== 'slot-a' || !/^cura-reservation-[a-f0-9]{32}$/.test(c.resource.incarnation) ||
      c.subject.iss !== 'https://identity.cura.kedgeflow.internal:8443/realms/kedgeflow-pilot' ||
      c.subject.sub !== 'd0b36f01-1188-4f01-907a-000000000001' || c.workload !== AGENT ||
      Object.keys(c.proposalKeys).length !== 1 || !hex(c.descriptorDigest) ||
      !label(c.policy.id) || c.policy.epoch !== 1 || !hex(c.policy.digest) ||
      !label(c.providerId) || !label(c.question.id) || !label(c.question.schema) ||
      !hex(c.question.digest) || !label(c.resultSchema.id) || !label(c.resultSchema.schema) ||
      c.resultSchema.digest !== digest('result-schema', RESULT_SCHEMA) ||
      ![c.evidenceKeyId,c.manifestKeyId,c.authorizationKeyId].every(label) ||
      new Set([c.evidenceKeyId,c.manifestKeyId,...Object.keys(c.proposalKeys)]).size !== 3 ||
      b64(c.evidencePublicKey).length !== 32 || b64(c.manifestPublicKey).length !== 32 ||
      c.evidencePublicKey === c.manifestPublicKey ||
      b64(c.authorizationKey).length !== 32 || b64(c.dpopThumbprint).length !== 32 ||
      !Number.isSafeInteger(c.until) || c.until <= 0) throw Error('closed observer contract');
  for (const [id, key] of Object.entries(c.proposalKeys)) {
    if (!label(id)) throw Error('proposal key id'); publicKey(key);
  }
  return c;
}

export function jwt(raw) {
  if (typeof raw !== 'string' || raw.length > 16 << 10) throw Error('JWT bound');
  const parts = raw.split('.'); if (parts.length !== 3) throw Error('JWT framing');
  const signature = b64(parts[2]); if (signature.length !== 64) throw Error('JWT signature');
  return { header: strictJson(utf8(b64(parts[0]))),
    claims: strictJson(utf8(b64(parts[1]))),
    input: Buffer.from(parts[0] + '.' + parts[1]), signature };
}

export function authenticate(headers, c, now) {
  if (now >= c.until || typeof headers.authorization !== 'string' ||
      !headers.authorization.startsWith('DPoP ')) throw Error('closed authentication');
  const token = headers.authorization.slice(5), access = jwt(token);
  validateKeycloakToken(access.header, access.claims, {clientId:'kf-pilot-agent'});
  const a = access.claims;
  if (access.header.kid !== c.authorizationKeyId ||
      !verify(null, access.input, publicKey(c.authorizationKey), access.signature) ||
      a.iss !== c.subject.iss || a.sub !== c.subject.sub ||
      a.aud !== 'urn:kedgeflow:delegated-admission' ||
      !Number.isSafeInteger(a.exp) || !Number.isSafeInteger(a.iat) ||
      a.iat < 0 || a.iat >= a.exp || a.iat * 1000 > now + 5000 ||
      a.exp * 1000 <= now || !Number.isSafeInteger(a.exp * 1000) ||
      a.cnf.jkt !== c.dpopThumbprint || typeof a.scope !== 'string') throw Error('subject binding');
  const scopes = a.scope.trim().split(/\s+/);
  if (!same([...scopes].sort(), [...SCOPES].sort())) throw Error('closed scopes');
  const proof = jwt(headers.dpop), h = proof.header, p = proof.claims;
  exact(h, ['alg','typ','jwk']); exact(h.jwk, ['crv','kty','x']);
  exact(p, ['jti','htm','htu','iat','ath']);
  if (h.alg !== 'EdDSA' || h.typ !== 'dpop+jwt' || h.jwk.kty !== 'OKP' ||
      h.jwk.crv !== 'Ed25519' || hash(canonical(h.jwk)).toString('base64url') !== c.dpopThumbprint ||
      !verify(null, proof.input, publicKey(h.jwk.x), proof.signature) ||
      typeof p.jti !== 'string' || !p.jti || Buffer.byteLength(p.jti) > 512 ||
      p.htm !== 'POST' || p.htu !== EXTERNAL || !Number.isSafeInteger(p.iat) ||
      p.iat < Math.floor(now/1000) - 60 || p.iat > Math.floor(now/1000) + 5 ||
      p.ath !== hash(token).toString('base64url')) throw Error('DPoP binding');
  return { replayId: hash(c.dpopThumbprint + ':' + p.jti).toString('hex'),
    delegation: { access_token_digest: hash(token).toString('hex'), dpop_jkt:c.dpopThumbprint,
      authorization_server:a.iss, token_audience:a.aud, scopes, expires_at:a.exp*1000 } };
}

export function rowState(row, c) {
  exact(row, ['tenant','conflict_domain','resource_id','incarnation','version',
    'last_fence','reservation','active']);
  const decimal = x => typeof x === 'string' && /^(0|[1-9][0-9]{0,15})$/.test(x) &&
    Number.isSafeInteger(Number(x));
  if (row.tenant !== c.tenant || row.resource_id !== c.resource.id ||
      row.incarnation !== c.resource.incarnation || row.conflict_domain !== 'cura-sql-pilot:reservations' ||
      !decimal(row.version) || Number(row.version) < 1 || !decimal(row.last_fence) ||
      !label(row.reservation) || typeof row.active !== 'boolean') throw Error('registered SQL state');
  return digest('cura-postgres-observation', row);
}

function parameters(value, c) {
  exact(value, SQL_SCHEMA.required);
  if (value.resource_id !== c.resource.id || !Number.isSafeInteger(value.expected_version) ||
      value.expected_version < 1 || value.expected_version > 9007199254740990 ||
      !label(value.reservation)) throw Error('registered SQL parameters');
}

export function observation(body, row, c, identity, keys, now) {
  const state = rowState(row, c);
  if (now >= c.until) throw Error('window expired');
  if (body.operation === 'baseline') {
    exact(body, ['operation','parameters']); parameters(body.parameters, c);
    if (String(body.parameters.expected_version) !== row.version) throw Error('stale SQL version');
    return {resource:c.resource, version:row.version, state_digest:state, observed_at:now,
      expires_at:Math.min(now+60000,c.until)};
  }
  exact(body, ['proposal','proposal_digest']);
  const envelope = verifyRecord(body.proposal, 'proposal', c.proposalKeys), p = envelope.payload;
  exact(p, ['qid','tenant','subject','workload_id','delegation','intent','action','resources',
    'parameters','dependencies','baseline_state','requested_completion','created_at','workflow']);
  exact(p.action, ['id','version','digest']); parameters(p.parameters, c);
  if (!label(p.qid) || typeof p.intent !== 'string' || p.intent.length > 4096 ||
      p.tenant !== c.tenant || !same(p.subject,c.subject) || p.workload_id !== AGENT ||
      !same(p.delegation,identity.delegation) || !same(p.resources,[c.resource]) ||
      !same(p.dependencies,[]) || p.workflow !== null || p.requested_completion !== 'dispatch_bound' ||
      p.action.id !== SQL_ACTION || p.action.version !== '1.0' ||
      p.action.digest !== c.descriptorDigest || recordDigest(envelope) !== body.proposal_digest ||
      String(p.parameters.expected_version) !== row.version ||
      !Number.isSafeInteger(p.created_at) || p.created_at > now || now-p.created_at >= 60000 ||
      !Array.isArray(p.baseline_state) || p.baseline_state.length !== 1) throw Error('proposal binding');
  const baseline = p.baseline_state[0];
  exact(baseline, ['resource','version','state_digest','observed_at','expires_at']);
  if (!same(baseline.resource,c.resource) || baseline.version !== row.version ||
      baseline.state_digest !== state || !Number.isSafeInteger(baseline.observed_at) ||
      !Number.isSafeInteger(baseline.expires_at) || baseline.observed_at > p.created_at ||
      now-baseline.observed_at >= 60000 || baseline.expires_at <= now ||
      baseline.expires_at > baseline.observed_at+60000) throw Error('baseline binding');
  const expires = Math.min(now+30000,baseline.expires_at,identity.delegation.expires_at,c.until);
  if (expires <= now) throw Error('freshness');
  const wid = 'cura-pilot:w:' + body.proposal_digest.slice(0,24) + ':' + now;
  const evidence = signedRecord('evidence', {wid, provider_id:c.providerId, provider_version:'1.0',
    question_ref:c.question, proposal_digest:body.proposal_digest, state_scope:[c.resource],
    state_digest:state, result_schema:c.resultSchema, result:{version:row.version,
      reservation:row.reservation,active:row.active,satisfied:row.active},
    observed_at:now,expires_at:expires,provenance_refs:[],exposure_domains:['cura-pilot:postgres']},
    c.evidenceKeyId,keys.evidence);
  const manifest = signedRecord('manifest', {mid:'cura-pilot:manifest:'+body.proposal_digest.slice(0,24)+':'+now,
    proposal_digest:body.proposal_digest,policy:c.policy,witnesses:[{witness:{id:wid,
      schema:'https://kedgeflow.dev/spec/v0.9/kedgeflow.schema.json#/$defs/Evidence',
      digest:recordDigest(strictJson(evidence))},obligation_id:'reservation-current',
      execution_relevant:true,expires_at:expires}],assembled_at:now},c.manifestKeyId,keys.manifest);
  return {manifest,witnesses:[evidence]};
}

async function protectedFile(path, uid, mode) {
  const info = await lstat(path);
  if (!info.isFile() || info.nlink !== 1 || info.uid !== uid || (info.mode & 0o7777) !== mode ||
      info.size > 1 << 20) throw Error('configuration custody');
  return readFile(path);
}

export async function consume(root, id, now) {
  const paths = await readdir(root); if (paths.length > 16384) throw Error('replay capacity');
  for (const name of paths) {
    if (!/^[a-f0-9]{64}$/.test(name)) throw Error('replay state');
    const raw = await protectedFile(join(root,name),process.getuid(),0o600);
    const expires = Number(raw.toString());
    if (!Number.isSafeInteger(expires) || expires > now+66000) throw Error('replay clock/state');
    if (expires <= now) await unlink(join(root,name));
  }
  const file = await open(join(root,id),'wx',0o600);
  try {await file.writeFile(String(now+66000));await file.sync();} finally {await file.close();}
  // Persist the directory entry before releasing a signed result.
  const directory = await open(root,'r');try {await directory.sync();} finally {await directory.close();}
}

function peerIdentity(socket, expected) {
  if (!socket.authorized) throw Error('unverified peer');
  const cert = new X509Certificate(socket.getPeerCertificate().raw);
  const uris = cert.subjectAltName.split(', ').filter(x=>x.startsWith('URI:'));
  if (!same(uris,['URI:'+expected])) throw Error('unexpected peer identity');
}

async function bodyBytes(req) {
  const chunks=[];let size=0;
  for await (const chunk of req) {size+=chunk.length;if (size>MAX_BODY) throw Error('body bound');chunks.push(chunk);}
  return utf8(Buffer.concat(chunks));
}

function forward(raw, headers, tls) {
  return new Promise((resolve,reject)=>{
    const req = request(UPSTREAM,{...tls,method:'POST',agent:false,rejectUnauthorized:true,
      minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['http/1.1'],
      headers:{authorization:headers.authorization,dpop:headers.dpop,'content-type':'application/json'},
      checkServerIdentity(host,cert) {const error=checkServerIdentity(host,cert);if (error)return error;
        const uris=new X509Certificate(cert.raw).subjectAltName.split(', ').filter(x=>x.startsWith('URI:'));
        if (!same(uris,['URI:'+SQL_OBSERVER]))return Error('upstream peer identity');}},res=>{
        bodyBytes(res).then(body=>{if (res.statusCode!==200)throw Error('source refused');
          strictJson(body);resolve(body);}).catch(reject);
      });
    req.setTimeout(5000,()=>req.destroy(Error('deadline')));req.on('error',reject);req.end(raw);
  });
}

export async function main(configPath, checkOnly=false) {
  if (process.platform !== 'linux' || process.getuid() === 0) throw Error('nonroot Linux service');
  const config = strictJson((await protectedFile(configPath,0,0o440)).toString());
  exact(config,['mode','contract','tlsRoot','replayRoot']);
  const c=validateContract(config.contract), role=config.mode;
  if (!['source','relay'].includes(role) || config.tlsRoot !==
      (role==='source'?'/etc/kedgeflow/sql-observer':'/etc/kedgeflow/evidence-relay') ||
      config.replayRoot !== '/var/lib/kedgeflow/pilot/sql-observer/replay') throw Error('service profile');
  const tls={ca:await protectedFile(join(config.tlsRoot,'ca.pem'),0,0o444),
    cert:await protectedFile(join(config.tlsRoot,'identity.pem'),0,0o444),
    key:await protectedFile(join(config.tlsRoot,'identity.key'),process.getuid(),0o400)};
  const keys={};
  if (role==='source') {
    const state=await lstat(config.replayRoot);
    if (!state.isDirectory() || state.uid!==process.getuid() || (state.mode&0o7777)!==0o700)
      throw Error('replay custody');
    for (const name of ['evidence','manifest']) {
      const seed=await protectedFile(join(config.tlsRoot,name+'.seed'),process.getuid(),0o400);
      const bytes=Buffer.from(seed.toString(),'base64');if(bytes.length!==32)throw Error('seed');
      keys[name]=privateSeed(bytes);
      if (publicBytes(keys[name]).toString('base64url')!==c[name+'PublicKey']) throw Error('proof key pin');
    }
  }
  const ca=role==='relay'?[await protectedFile('/etc/kedgeflow/evidence-relay/spire-ca.pem',0,0o444)]:tls.ca;
  let busy=false;
  const server=createServer({...tls,ca,requestCert:true,rejectUnauthorized:true,
    minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['http/1.1']},async(req,res)=>{
    let acquired=false;
    try {
      if (busy || req.method!=='POST' || req.url!=='/evidence' || Date.now()>=c.until)
        throw Error('request profile');
      busy=true;acquired=true;
      peerIdentity(req.socket,role==='source'?RELAY:AGENT);
      for (const name of ['authorization','dpop','content-type']) {
        if (req.rawHeaders.filter((x,i)=>i%2===0&&x.toLowerCase()===name).length!==1)
          throw Error('ambiguous headers');
      }
      if (req.headers['content-type']!=='application/json')throw Error('content type');
      const raw=await bodyBytes(req),body=strictJson(raw);
      const identity=authenticate(req.headers,c,Date.now());
      let result;
      if(role==='relay') result=await forward(raw,req.headers,tls);
      else {
        await consume(config.replayRoot,identity.replayId,Date.now());
        // Fixed zero-argument function. No request text, interpolation, URI, SQL or psql settings.
        const sql=await run('/opt/kedgeflow/runtime/postgres/bin/psql',[
          '-X','-A','-t','--no-password','-h','/run/kedgeflow-postgres','-p','5432',
          '-U','kf_observer','-d','kedgeflow','-v','ON_ERROR_STOP=1','-c',
          'SELECT kf_reservation.observe_cura();'],{timeout:3000,maxBuffer:8192,
          env:{PATH:'/usr/bin:/bin',LANG:'C',PGCONNECT_TIMEOUT:'2',
            PGOPTIONS:'-c statement_timeout=2000 -c default_transaction_read_only=on'}});
        const row=strictJson(sql.stdout.trim());
        result=canonical(observation(body,row,c,identity,keys,Date.now()));
      }
      res.writeHead(200,{'content-type':'application/json','cache-control':'no-store'});res.end(result);
    } catch {res.writeHead(403,{'content-type':'application/json','cache-control':'no-store'});
      res.end('{"status":"refused"}');} finally {if(acquired)busy=false;}
  });
  server.requestTimeout=5000;server.headersTimeout=5000;server.keepAliveTimeout=1000;
  server.maxConnections=16;server.maxRequestsPerSocket=1;
  server.on('tlsClientError',()=>{});server.on('clientError',(_,socket)=>socket.destroy());
  if(checkOnly) {
    console.log(JSON.stringify({status:'protected_configuration_passed',role,execution_authority:false}));
    return;
  }
  await new Promise((resolve,reject)=>{server.once('error',reject);
    server.listen(role==='source'?8452:8444,'0.0.0.0',resolve);});
  process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
  console.log(JSON.stringify({status:'listening',role,resource:c.resource.id,execution_authority:false}));
}

if (process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if (![3,4].includes(process.argv.length) || (process.argv.length===4&&process.argv[3]!=='--check')) {
    console.log('{"status":"failed","phase":"arguments"}');process.exitCode=1;
  } else main(process.argv[2],process.argv[3]==='--check').catch(()=>{
    console.log('{"status":"failed","phase":"protected_startup"}');process.exitCode=1;});
}
