import { connect } from 'cloudflare:sockets';
import { email } from './crypto.js';
export async function sendCode(env,to,code) {
 if(!email(to)||!email(env.SMTP_FROM)||!/^\d{6}$/.test(code))throw Error('Invalid mail settings');
 let socket, reader, writer, buffer='', total=0, timer, stage='connection';
 const host=String(env.SMTP_HOST||'').trim(), port=Number(env.SMTP_PORT);
 const decoder=new TextDecoder(), encoder=new TextEncoder();
 async function reply(expected) {
  for(let lines=0;lines<100;lines++) {
   while(!buffer.includes('\r\n')) { const r=await reader.read(); if(r.done)throw Error('SMTP disconnected'); total+=r.value.length;if(total>65536)throw Error('SMTP reply too large');buffer+=decoder.decode(r.value,{stream:true}); }
   const pos=buffer.indexOf('\r\n'),line=buffer.slice(0,pos);buffer=buffer.slice(pos+2);
   if(!/^\d{3}[ -]/.test(line))throw Error('Invalid SMTP reply');
   if(line[3]===' ') {if(!expected.includes(Number(line.slice(0,3))))throw Object.assign(Error('SMTP rejected request'),{smtpCode:Number(line.slice(0,3))});return;}
  }throw Error('SMTP reply too long');
 }
 async function command(s,codes) {await writer.write(encoder.encode(s+'\r\n'));await reply(codes);}
 const run=async()=>{
  if(!/^[a-zA-Z0-9.-]+$/.test(host)||![465,443,8465].includes(port))throw Error('Invalid SMTP_HOST or implicit-TLS SMTP_PORT; use hostname only and port 465, 443, or 8465.');
  socket=connect({hostname:host,port},{secureTransport:'on'});
  socket.closed.catch(()=>{});
  reader=socket.readable.getReader();writer=socket.writable.getWriter();
  socket.opened.catch(()=>{});stage='server greeting';await reply([220]);stage='EHLO';await command('EHLO secret.local',[250]);
  stage='authentication';await command('AUTH LOGIN',[334]);
  const base=s=>btoa(String.fromCharCode(...encoder.encode(s)));
  await command(base(env.SMTP_USER),[334]);await command(base(env.SMTP_PASSWORD),[235]);
  stage='sender address';await command('MAIL FROM:<'+env.SMTP_FROM+'>',[250]);stage='recipient address';await command('RCPT TO:<'+to+'>',[250,251]);stage='message submission';await command('DATA',[354]);
  await command(['From: Secret <'+env.SMTP_FROM+'>','To: <'+to+'>','Subject: Your password retrieval code','Date: '+new Date().toUTCString(),'Message-ID: <'+crypto.randomUUID()+'@'+env.SMTP_FROM.split('@')[1]+'>','MIME-Version: 1.0','Content-Type: text/plain; charset=UTF-8','','Your verification code is: '+code,'','This code expires in 10 minutes, or sooner if the link expires.','Enter it only on the Secret page where you requested it.','If you did not request this code, ignore this email.','','.'].join('\r\n'),[250]);
 };
 try { await Promise.race([run(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('SMTP timeout')),12000);})]); }
 catch(e){const status=Number.isInteger(e.smtpCode)?' (SMTP '+e.smtpCode+')':'';const hint=stage==='authentication'?'Check the SMTP2GO SMTP user and SMTP_PASSWORD.':stage==='sender address'||stage==='message submission'?'Check the verified sender/domain and sending quota in SMTP2GO.':'Check SMTP2GO activity and the TLS host/port settings.';let detail='';
 if(stage==='connection'){
  detail=String(e?.message||'Unknown connection error');
  for(const value of [env.SMTP_PASSWORD,env.SMTP_USER,to,code]){if(value){detail=detail.split(String(value)).join('[redacted]');const encoded=btoa(String.fromCharCode(...new TextEncoder().encode(String(value))));detail=detail.split(encoded).join('[redacted]');}}
  detail=' Connection detail: '+detail.replace(/[\x00-\x1f\x7f]/g,' ').slice(0,400);
 }
 const failure=Error('SMTP failed at '+stage+status+'. '+hint+detail);failure.publicSmtpError=true;throw failure;}
 finally {clearTimeout(timer);if(socket)socket.close().catch(()=>{});}
}
