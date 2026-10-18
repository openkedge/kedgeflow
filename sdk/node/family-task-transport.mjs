// Fixed family peer discovery and RPC transport. TLS/identity material stays in
// the host adapter; command parts contain no credentials or fetchable references.
import { request } from 'node:https';
import { randomUUID, sign } from 'node:crypto';
import { canonical, hash, publicBytes } from './records.mjs';
import { fixedHttps, mtlsFetch } from './transport.mjs';
export function familyTaskFetch({tls,endpoint,tokenProvider,dpopKey,now=Date.now}) {
  fixedHttps(endpoint);
  if (typeof tokenProvider !== 'function' || typeof now !== 'function') throw new Error('protected identity provider required');
  const cardUrl=new URL('/.well-known/agent-card.json',endpoint).href;
  const post=mtlsFetch({...tls,allowedUrls:[endpoint]});
  const jwk={kty:'OKP',crv:'Ed25519',x:publicBytes(dpopKey).toString('base64url')};
  return async (input,init={}) => {
    const url=typeof input==='string'?input:input instanceof URL?input.href:input.url;
    if (url===cardUrl && (init.method??'GET')==='GET' && init.body===undefined) {
      return new Promise((resolve,reject)=>{
        let timer; let size=0; const chunks=[];
        const fail=()=>{clearTimeout(timer);reject(new Error('family card transport unavailable'));};
        const req=request(url,{method:'GET',ca:tls.ca,cert:tls.cert,key:tls.key,rejectUnauthorized:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',ALPNProtocols:['http/1.1'],headers:Object.fromEntries(new Headers(init.headers)),agent:false,signal:init.signal},res=>{
          res.on('data',chunk=>{size+=chunk.length;if(size>32768){req.destroy();fail();}else chunks.push(chunk);});
          res.on('error',fail);
          res.on('end',()=>{clearTimeout(timer);if(size>32768)return;const r=new Response(Buffer.concat(chunks),{status:res.statusCode,headers:res.headers});Object.defineProperty(r,'url',{value:url});resolve(r);});
        });
        req.on('error',fail);timer=setTimeout(()=>{req.destroy();fail();},5000);req.end();
      });
    }
    if(url!==endpoint || init.method!=='POST') throw new Error('unapproved family peer request');
    const token=await tokenProvider();
    if(typeof token!=='string'||!token||token.length>32768)throw new Error('bounded subject token required');
    const issued=Math.floor(now()/1000);
    if(!Number.isSafeInteger(issued))throw new Error('valid clock required');
    const claims={jti:randomUUID(),htm:'POST',htu:endpoint,iat:issued,ath:hash(token).toString('base64url')};
    const unsigned=[{alg:'EdDSA',typ:'dpop+jwt',jwk},claims].map(v=>Buffer.from(canonical(v)).toString('base64url')).join('.');
    const headers=new Headers(init.headers);
    headers.set('Authorization',`DPoP ${token}`);
    headers.set('DPoP',`${unsigned}.${sign(null,Buffer.from(unsigned),dpopKey).toString('base64url')}`);
    return post(url,{...init,headers});
  };
}
