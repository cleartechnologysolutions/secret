import { random, mac, equal, json } from './crypto.js';
export class SecretStore {
 constructor(ctx,env){this.ctx=ctx;this.env=env;}
 async alarm(){await this.ctx.storage.deleteAll();}
 fetch(req){return this.ctx.blockConcurrencyWhile(()=>this.handle(req));}
 async handle(req){
 const s=this.ctx.storage, action=new URL(req.url).pathname;
 const b=await req.json(); let r=await s.get('record');
 if(action==='/create'){
  if(r)return json({error:'Already exists'},409);
  await s.put('record',{...b,attempts:0,sends:0,lastSend:0});await s.setAlarm(b.expires);return json({ok:true});
 }
 if(!r||r.expires<=Date.now()){await s.deleteAll();return json({error:'This link has expired or has already been used.'},410);}
 if(action==='/code'){
  if(!equal(b.email,r.email))return json({error:'Unable to send a code. Check the recipient email.'},400);
  if(r.sends>=5||r.attempts>=10)return json({error:'Verification limit reached. Ask the sender for a new link.'},429);
  if(Date.now()-r.lastSend<60000)return json({error:'Wait one minute before requesting another code.'},429);
  const a=new Uint32Array(1);do{crypto.getRandomValues(a);}while(a[0]>=4294000000);
  const code=String(a[0]%1000000).padStart(6,'0');
  r.salt=random();r.codeHash=await mac(this.env.ADMIN_PASSWORD,'code:'+r.salt+':'+code);r.codeExpires=Math.min(Date.now()+600000,r.expires);r.lastSend=Date.now();r.sends++;delete r.grant;
  await s.put('record',r);
  try{await this.send(r.email,code);}catch{delete r.codeHash;await s.put('record',r);return json({error:'Email delivery failed. Check SMTP settings or retry in one minute.'},502);}
  return json({ok:true});
 }
 if(action==='/verify'){
  if(r.attempts>=10)return json({error:'Verification limit reached. Ask for a new link.'},429);
  r.attempts++;
  const valid=r.codeHash&&r.codeExpires>Date.now()&&equal(r.codeHash,await mac(this.env.ADMIN_PASSWORD,'code:'+r.salt+':'+b.code));
  if(!valid){await s.put('record',r);return json({error:'Incorrect or expired code.'},400);}
  const grant=random();r.grant=await mac(this.env.ADMIN_PASSWORD,'grant:'+grant);r.grantExpires=Math.min(Date.now()+300000,r.expires);delete r.codeHash;await s.put('record',r);return json({grant});
 }
 if(action==='/reveal'){
  if(!r.grant||r.grantExpires<=Date.now()||!equal(r.grant,await mac(this.env.ADMIN_PASSWORD,'grant:'+b.grant)))return json({error:'Verify your email again before revealing.'},403);
  const result={ciphertext:r.ciphertext,iv:r.iv};await s.deleteAll();return json(result);
 }
 return json({error:'Not found'},404);
 }
 async send(to,code){const {sendCode}=await import('./smtp.js');return sendCode(this.env,to,code);}
}
