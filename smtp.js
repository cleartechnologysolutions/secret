import { connect } from 'cloudflare:sockets';
import { email } from './crypto.js';
export async function sendCode(env,to,code) {
 if(!email(to)||!email(env.SMTP_FROM)||!/^\d{6}$/.test(code))throw Error('Invalid mail settings');
 const socket=connect({hostname:env.SMTP_HOST,port:Number(env.SMTP_PORT)},{secureTransport:'on'});
 socket.closed.catch(()=>{});
 const reader=socket.readable.getReader(), writer=socket.writable.getWriter();
 let buffer='', total=0, timer;
 const decoder=new TextDecoder(), encoder=new TextEncoder();
 async function reply(expected) {
  for(let lines=0;lines<100;lines++) {
   while(!buffer.includes('\r\n')) { const r=await reader.read(); if(r.done)throw Error('SMTP disconnected'); total+=r.value.length;if(total>65536)throw Error('SMTP reply too large');buffer+=decoder.decode(r.value,{stream:true}); }
   const pos=buffer.indexOf('\r\n'),line=buffer.slice(0,pos);buffer=buffer.slice(pos+2);
   if(!/^\d{3}[ -]/.test(line))throw Error('Invalid SMTP reply');
   if(line[3]===' ') {if(!expected.includes(Number(line.slice(0,3))))throw Error('SMTP rejected request');return;}
  }throw Error('SMTP reply too long');
 }
 async function command(s,codes) {await writer.write(encoder.encode(s+'\r\n'));await reply(codes);}
 const run=async()=>{
  await socket.opened;await reply([220]);await command('EHLO secret.local',[250]);
  await command('AUTH LOGIN',[334]);
  const base=s=>btoa(String.fromCharCode(...encoder.encode(s)));
  await command(base(env.SMTP_USER),[334]);await command(base(env.SMTP_PASSWORD),[235]);
  await command('MAIL FROM:<'+env.SMTP_FROM+'>',[250]);await command('RCPT TO:<'+to+'>',[250,251]);await command('DATA',[354]);
  await command(['From: Secret <'+env.SMTP_FROM+'>','To: <'+to+'>','Subject: Your password retrieval code','Date: '+new Date().toUTCString(),'Message-ID: <'+crypto.randomUUID()+'@'+env.SMTP_FROM.split('@')[1]+'>','MIME-Version: 1.0','Content-Type: text/plain; charset=UTF-8','','Your verification code is: '+code,'','This code expires in 10 minutes, or sooner if the link expires.','Enter it only on the Secret page where you requested it.','If you did not request this code, ignore this email.','','.'].join('\r\n'),[250]);
 };
 try { await Promise.race([run(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('SMTP timeout')),12000);})]); }
 finally {clearTimeout(timer);socket.close().catch(()=>{});}
}
