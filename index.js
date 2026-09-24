import { page } from './page.js';
import { random,email,json } from './crypto.js';
export { SecretStore } from './store.js';
const headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",'Permissions-Policy':'camera=(), microphone=(), geolocation=()'};
import { client } from './client.js';
import { css } from './style.js';
async function body(req){const reader=req.body?.getReader();if(!reader)throw Error('body');let text='',size=0;const d=new TextDecoder();while(true){const r=await reader.read();if(r.done)break;size+=r.value.length;if(size>20000){await reader.cancel();throw Error('size');}text+=d.decode(r.value,{stream:true});}return JSON.parse(text+d.decode());}
async function handler(req,env){
 const url=new URL(req.url),p=url.pathname;
 if(req.method==='GET'){
  if(p==='/client.js')return new Response(client,{headers:{'Content-Type':'application/javascript'}});
  if(p==='/style.css')return new Response(css,{headers:{'Content-Type':'text/css'}});
  if(p==='/'||/^\/s\/[A-Za-z0-9_-]{43}$/.test(p))return new Response(page,{headers:{'Content-Type':'text/html; charset=utf-8'}});
  if(p==='/api/session')return json({ready:ready(env),build:'1.0.2'});
  return json({error:'Not found'},404);
 }
 if(req.method!=='POST')return json({error:'Method not allowed'},405);
 if(req.headers.get('Origin')!==url.origin||!req.headers.get('Content-Type')?.startsWith('application/json'))return json({error:'Request not allowed'},403);
 if(!ready(env))return json({error:'Setup needed: add SMTP_PASSWORD in Worker runtime secrets.'},503);
 const ip=req.headers.get('CF-Connecting-IP')||'local';
 if(env.REQUEST_LIMITER&&!(await env.REQUEST_LIMITER.limit({key:ip})).success)return json({error:'Too many requests. Try again in a minute.'},429);
 let b;try{b=await body(req);}catch{return json({error:'Invalid request'},400);}
 if(p==='/api/create'){
  if(env.CREATE_LIMITER&&!(await env.CREATE_LIMITER.limit({key:ip})).success)return json({error:'Too many new links. Try again in a minute.'},429);
  if(!email(b.email)||!Number.isInteger(b.ttl)||b.ttl<300||b.ttl>172800||!/^[-\w]{24,12000}$/.test(b.ciphertext)||!/^[-\w]{16}$/.test(b.iv))return json({error:'Check email, password size, and expiration.'},400);
  const id=random(),expires=Date.now()+b.ttl*1000;const r=await env.SECRETS.get(env.SECRETS.idFromName(id)).fetch('https://internal/create',{method:'POST',body:JSON.stringify({email:b.email.toLowerCase(),ciphertext:b.ciphertext,iv:b.iv,expires})});
  if(!r.ok)return r;return json({id,expires});
 }
 const match=p.match(/^\/api\/s\/([A-Za-z0-9_-]{43})\/(code|verify|reveal)$/);
 if(match){if(match[2]==='code'){if(!email(b.email))return json({error:'Enter a valid email.'},400);b.email=b.email.toLowerCase();if(env.MAIL_LIMITER&&!(await env.MAIL_LIMITER.limit({key:b.email})).success)return json({error:'Too many email requests. Try again in a minute.'},429);}if(match[2]==='verify'&&!/^\d{6}$/.test(b.code))return json({error:'Enter the six-digit code.'},400);if(match[2]==='reveal'&&!/^[\w-]{43}$/.test(b.grant))return json({error:'Verification required.'},403);
 return env.SECRETS.get(env.SECRETS.idFromName(match[1])).fetch('https://internal/'+match[2],{method:'POST',body:JSON.stringify(b)});}
 return json({error:'Not found'},404);
}
function ready(e){return !!e.SMTP_PASSWORD&&!!e.SMTP_USER&&!!e.SMTP_HOST&&email(e.SMTP_FROM);}
export default {async fetch(req,env){let r;try{r=await handler(req,env);}catch{r=json({error:'Request failed. Please try again.'},500);}const h=new Headers(r.headers);for(const[k,v]of Object.entries(headers))h.set(k,v);return new Response(r.body,{status:r.status,headers:h});}};
