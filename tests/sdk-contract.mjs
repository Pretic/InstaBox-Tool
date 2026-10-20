// Runs the actual published SDK with a fake HTTP transport; no live account is contacted.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { policyOf, verdict, run } from '../platform.mjs';
const { Sandbox } = await import(pathToFileURL(process.env.SDK_ENTRY).href);
let m={id:'m_contract',name:'contract-machine',state:'running',createdAt:'2026-01-01T00:00:00Z',
  autoSuspendAfterSeconds:1800,timeoutAt:'2027-01-01T00:00:00Z'};
const calls=[];
async function transport(url,options={}) {
  const p=new URL(url).pathname;
  const method=options.method||'GET';
  if(p!=='/v1/machines/m_contract')throw Error('Unexpected request '+method+' '+p);
  if(method==='PATCH') {
    const body=JSON.parse(options.body);calls.push(body);
    if(Object.hasOwn(body,'autoSuspendAfterSeconds'))m.autoSuspendAfterSeconds=body.autoSuspendAfterSeconds;
    if(body.timeoutSeconds===0)m.timeoutAt=null;
  }else if(method!=='GET')throw Error('Unexpected method');
  // The SDK accepts the API's data envelope. Root fields also let this check cover
  // deployments returning the machine directly, without any live requests.
  return new Response(JSON.stringify({...m,data:{...m}}),{status:200,headers:{'content-type':'application/json'}});
}
const box=await Sandbox.connect('m_contract',{apiKey:'ibk_NOT_A_REAL_KEY',resume:false,fetch:transport});
await box.setAutoSuspend(0);await box.setTimeout(0);
assert.deepEqual(calls,[{autoSuspendAfterSeconds:0},{timeoutSeconds:0}]);
const info=await box.getInfo();
assert.equal(info.machine.autoSuspendAfterSeconds,0);
assert.equal(policyOf(info).idleSeconds,0);
assert.equal(verdict(policyOf(info)),'confirmed');
console.log('Official SDK contract verified: zero retained via raw machine; both PATCH fields correct.');
console.log('SDK top-level autoSuspendMs type:',typeof info.autoSuspendMs);
m.autoSuspendAfterSeconds=null;
assert.equal(verdict(policyOf(await box.getInfo())),'confirmed');
console.log('Official nullable idle field is treated as OFF; an absent field stays unknown.');

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ib-wire-'));
let m2={...m,autoSuspendAfterSeconds:1800,timeoutAt:null};
const mutations=[];
async function lifecycleTransport(url,options={}) {
  const p=new URL(url).pathname, method=options.method||'GET';
  if(p!=='/v1/machines/m_contract' && p!=='/v1/machines') throw Error('Unexpected endpoint');
  if(method==='PATCH') {
    const body=JSON.parse(options.body);mutations.push(body);
    if(Object.hasOwn(body,'timeoutSeconds')){m2.timeoutAt=null;m2.autoSuspendAfterSeconds=1800;}
    if(Object.hasOwn(body,'autoSuspendAfterSeconds'))m2.autoSuspendAfterSeconds=body.autoSuspendAfterSeconds;
  }else assert.equal(method,'GET');
  const payload=p==='/v1/machines'?{machines:[{...m2}]}:{...m2};
  return new Response(JSON.stringify({...payload,data:payload}),{status:200,headers:{'content-type':'application/json'}});
}
try{
  const deps={home:dir,env:{},Sandbox,
    sdkOptions:{apiKey:'ibk_CONTRACT_ONLY',fetch:lifecycleTransport},sleep:async()=>{},
    io:{say:()=>{},ask:async()=>{throw Error('Unexpected prompt');}}};
  assert.equal(await run(['apply'],deps),0);
  assert.deepEqual(mutations,[{autoSuspendAfterSeconds:0}]);
  m2.timeoutAt='2027-01-01T00:00:00Z';mutations.length=0;
  assert.equal(await run(['apply'],deps),0);
  assert.deepEqual(mutations,[{timeoutSeconds:0},{autoSuspendAfterSeconds:0}]);
  console.log('Actual SDK application flow: no redundant timeout, idle written last.');
}finally{fs.rmSync(dir,{recursive:true,force:true});}
