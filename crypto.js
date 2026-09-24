export const enc = new TextEncoder();
export const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
export const random = (n=32) => b64(crypto.getRandomValues(new Uint8Array(n)));
export async function mac(key, data) { const k=await crypto.subtle.importKey('raw',enc.encode(key),{name:'HMAC',hash:'SHA-256'},false,['sign']); return b64(await crypto.subtle.sign('HMAC',k,enc.encode(data))); }
export function equal(a,b) { if(typeof a!=='string'||typeof b!=='string')return false; let n=a.length^b.length; for(let i=0;i<Math.max(a.length,b.length);i++)n|=(a.charCodeAt(i)||0)^(b.charCodeAt(i)||0); return n===0; }
export function email(s) { return typeof s==='string' && s.length<=254 && /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$/.test(s); }
export const json=(data,status=200)=>Response.json(data,{status});
