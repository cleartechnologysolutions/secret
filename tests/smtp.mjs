import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
// Replace only the platform socket import with a simulated SMTP transport.
let lines=[],sent=[];const encoder=new TextEncoder();let control;
globalThis.__smtpConnect=()=>{const readable=new ReadableStream({start(c){control=c;c.enqueue(encoder.encode('220 mock ready\r\n'));}});return{opened:Promise.resolve(),closed:Promise.resolve(),close:async()=>{},readable,writable:new WritableStream({write(bytes){const s=new TextDecoder().decode(bytes);sent.push(s);let response;if(s.startsWith('EHLO'))response='250-mock\r\n250 AUTH LOGIN\r\n';else if(s.startsWith('AUTH'))response='334 user\r\n';else if(sent.length===3)response='334 password\r\n';else if(sent.length===4)response='235 authenticated\r\n';else if(s==='DATA\r\n')response='354 continue\r\n';else response='250 accepted\r\n';control.enqueue(encoder.encode(response));}})};};
let source=await fs.readFile(new URL('../smtp.js',import.meta.url),'utf8');source=source.replace("import { connect } from 'cloudflare:sockets';","const connect=globalThis.__smtpConnect;").replace("'./crypto.js'",JSON.stringify(new URL('../crypto.js',import.meta.url).href));
const {sendCode}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
await sendCode({SMTP_HOST:'mock',SMTP_PORT:'465',SMTP_FROM:'sender@example.com',SMTP_USER:'user',SMTP_PASSWORD:'test-only'},'client@example.com','123456');
assert(sent.at(-1).includes('Your verification code is: 123456'));assert(sent.at(-1).endsWith('\r\n.\r\n'));assert(sent[1].startsWith('AUTH LOGIN'));assert.equal(sent.length,8);
await assert.rejects(()=>sendCode({SMTP_FROM:'sender@example.com'},'victim@example.com\r\nBcc:bad@example.com','123456'));
console.log('PASS SMTP multiline replies, authentication sequence, DATA termination and header injection rejection.');
