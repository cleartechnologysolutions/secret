import assert from 'node:assert/strict';
import {SecretStore} from '../store.js';
import worker from '../index.js';
import {random} from '../crypto.js';
class Storage{constructor(){this.map=new Map();}async get(k){return structuredClone(this.map.get(k));}async put(k,v){this.map.set(k,structuredClone(v));}async deleteAll(){this.map.clear();}async setAlarm(t){this.alarm=t;}}
const env={ADMIN_PASSWORD:'test-only-admin-password-very-long',SMTP_PASSWORD:'fake',SMTP_USER:'sender@example.com',SMTP_HOST:'example.com',SMTP_FROM:'sender@example.com'};
function store(){let queue=Promise.resolve();const ctx={storage:new Storage(),blockConcurrencyWhile(fn){const p=queue.then(fn);queue=p.catch(()=>{});return p;}};const o=new SecretStore(ctx,env);o.send=async(to,code)=>{o.sent={to,code};};return o;}
async function call(o,path,b={}){return o.fetch(new Request('https://internal/'+path,{method:'POST',body:JSON.stringify(b)}));}
const secret='Sensitive test password',raw=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12)),key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
const ciphertext=Buffer.from(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(secret))).toString('base64url');
const payload={email:'client@example.com',expires:Date.now()+60000,ciphertext,iv:Buffer.from(iv).toString('base64url')};
const o=store();assert.equal((await call(o,'create',payload)).status,200);assert(!JSON.stringify([...o.ctx.storage.map]).includes(secret));
assert.equal((await call(o,'reveal',{grant:'wrong'})).status,403);
assert.equal((await call(o,'code',{email:'wrong@example.com'})).status,400);assert(!o.sent);
assert.equal((await call(o,'code',{email:payload.email})).status,200);
assert.equal((await call(o,'code',{email:payload.email})).status,429);
assert.equal((await call(o,'verify',{code:'bad'})).status,400);
const grant=(await(await call(o,'verify',{code:o.sent.code})).json()).grant;assert(grant);
assert.equal((await call(o,'verify',{code:o.sent.code})).status,400);
const results=await Promise.all(Array.from({length:10},()=>call(o,'reveal',{grant})));assert.equal(results.filter(r=>r.status===200).length,1);assert.equal(results.filter(r=>r.status===410).length,9);
const encrypted=await results.find(r=>r.status===200).json();assert.equal(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv},key,Buffer.from(encrypted.ciphertext,'base64url'))),secret);assert.equal(o.ctx.storage.map.size,0);
const expired=store();await call(expired,'create',{...payload,expires:Date.now()-1});assert.equal((await call(expired,'code',{email:payload.email})).status,410);assert.equal(expired.ctx.storage.map.size,0);
const limited=store();await call(limited,'create',payload);await call(limited,'code',{email:payload.email});for(let i=0;i<10;i++)await call(limited,'verify',{code:'bad'});assert.equal((await call(limited,'verify',{code:limited.sent.code})).status,429);
const failed=store();failed.send=async()=>{throw Error('mail failed');};await call(failed,'create',payload);assert.equal((await call(failed,'code',{email:payload.email})).status,502);assert(!(await failed.ctx.storage.get('record')).codeHash);
const expiredCode=store();await call(expiredCode,'create',payload);await call(expiredCode,'code',{email:payload.email});let r=await expiredCode.ctx.storage.get('record');r.codeExpires=0;await expiredCode.ctx.storage.put('record',r);assert.equal((await call(expiredCode,'verify',{code:expiredCode.sent.code})).status,400);
const objects=new Map();env.SECRETS={idFromName:x=>x,get(id){if(!objects.has(id))objects.set(id,store());return {fetch:(url,init)=>objects.get(id).fetch(new Request(url,init))};}};
const request=(path,b,cookie)=>new Request('https://secret.example'+path,{method:'POST',headers:{Origin:'https://secret.example','Content-Type':'application/json',...(cookie?{Cookie:cookie}:{})},body:JSON.stringify(b)});
assert.equal((await worker.fetch(request('/api/create',{}),env)).status,403);
const login=await worker.fetch(request('/api/login',{password:env.ADMIN_PASSWORD}),env);assert.equal(login.status,200);const cookie=login.headers.get('set-cookie').split(';')[0];assert(cookie);
const created=await worker.fetch(request('/api/create',{...payload,ttl:300},cookie),env);assert.equal(created.status,200);const {id}=await created.json();assert.equal(id.length,43);
assert.equal((await worker.fetch(new Request('https://secret.example/s/'+id),env)).status,200);assert((await objects.get(id).ctx.storage.get('record')).ciphertext);
assert.equal((await worker.fetch(new Request('https://secret.example/api/s/'+id+'/reveal'),env)).status,404);
const wrongOrigin=request('/api/login',{password:env.ADMIN_PASSWORD});wrongOrigin.headers.set('Origin','https://evil.example');assert.equal((await worker.fetch(wrongOrigin,env)).status,403);
assert.equal((await worker.fetch(request('/api/create',{...payload,ttl:0},cookie),env)).status,400);
assert.equal(created.headers.get('cache-control'),'no-store');
console.log('PASS encryption, expiry, OTP attempts/expiry/reuse, cooldown, mail failure, atomic one-time retrieval, admin authentication, scanner GET safety, origin checks, and cache headers.');
