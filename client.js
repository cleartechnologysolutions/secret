export const client=String.raw`
const $=id=>document.getElementById(id), sections=['create','created','receive','ready','shown'];
let grant='',keyText=location.hash.slice(1),shareId=location.pathname.split('/')[2],busy=false;
function show(id){sections.forEach(s=>$(s).hidden=s!==id);}
function notice(s,error=false){$('notice').textContent=s;$('notice').className=error?'error':'';}
async function api(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const b=await r.json();if(!r.ok)throw Error(b.error||'Request failed');return b;}
function task(fn){return async e=>{e?.preventDefault();if(busy)return;busy=true;document.querySelectorAll('button').forEach(x=>x.disabled=true);notice('Working…');try{await fn();}catch(e){notice(e.message,true);}finally{busy=false;document.querySelectorAll('button').forEach(x=>x.disabled=false);}};}
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
const bytes=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),x=>x.charCodeAt(0));
async function copy(id){try{await navigator.clipboard.writeText($(id).value);notice('Copied.');}catch{$(id).select();notice('Select and copy the text above.');}}
$('createForm').onsubmit=task(async()=>{
 const plain=$('secret').value;if(!plain.trim())throw Error('Enter a password or note.');if(new TextEncoder().encode(plain).length>8000)throw Error('Keep the note under 8 KB.');
 const raw=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
 const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt']);
 const ciphertext=b64(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(plain)));
 const result=await api('/api/create',{email:$('recipient').value,ttl:Number($('ttl').value),ciphertext,iv:b64(iv)});
 $('link').value=location.origin+'/s/'+result.id+'#'+b64(raw);$('secret').value='';$('expires').textContent='Expires '+new Date(result.expires).toLocaleString();show('created');notice('Link created. Only the specified recipient can reveal it.');
});
$('copyLink').onclick=()=>copy('link');$('another').onclick=()=>{$('link').value='';show('create');notice('');};
$('emailForm').onsubmit=task(async()=>{await api('/api/s/'+shareId+'/code',{email:$('email').value});$('codeForm').hidden=false;notice('Code sent. If it doesn’t arrive, check your spam or junk folder and any email security quarantine. Codes expire within 10 minutes.');$('code').focus();});
$('codeForm').onsubmit=task(async()=>{const r=await api('/api/s/'+shareId+'/verify',{code:$('code').value});grant=r.grant;$('code').value='';show('ready');notice('Verified. Reveal within 5 minutes, before the link expires.');});
$('reveal').onclick=task(async()=>{
 const key=await crypto.subtle.importKey('raw',bytes(keyText),'AES-GCM',false,['decrypt']);
 let result;try{result=await api('/api/s/'+shareId+'/reveal',{grant});}catch(e){throw Error(e.message+' If retrieval was interrupted, the link may already be consumed.');}
 grant='';history.replaceState(null,'',location.pathname);
 try{$('revealed').value=new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(result.iv)},key,bytes(result.ciphertext)));}catch{throw Error('The link was consumed but could not be decrypted. Ask the sender for a new link.');}
 keyText='';show('shown');notice('Revealed once. Copy it now; refreshing cannot retrieve it again.');setTimeout(clearSecret,300000);
});
function clearSecret(){$('revealed').value='';show('shown');$('copySecret').hidden=true;$('clear').hidden=true;notice('Cleared. This link cannot be used again.');}
$('clear').onclick=clearSecret;$('copySecret').onclick=()=>copy('revealed');
addEventListener('pagehide',()=>{$('revealed').value='';$('secret').value='';});
addEventListener('pageshow',e=>{if(e.persisted)location.reload();});
(async()=>{try{if(shareId){if(!/^[\w-]{43}$/.test(keyText)||bytes(keyText).length!==32){notice('This link is incomplete. Ask the sender for the full link, including everything after #.',true);return;}show('receive');notice('');}else{const r=await(await fetch('/api/session')).json();show('create');notice(r.ready?'':'Setup needed: add SMTP_PASSWORD as Worker runtime secrets.',!r.ready);}}catch{notice('Unable to load. Please refresh.',true);}})();
`;
