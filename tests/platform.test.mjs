import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { policyOf, verdict, run } from '../platform.mjs';
const raw = (extra = {}) => ({ id: 'm_one', name: 'example-machine', state: 'running',
  createdAt: '2026-01-01T00:00:00Z', autoSuspendAfterSeconds: 0, ...extra });
// Deliberately reproduce the published SDK's lossy truthiness conversion.
function sdkInfo(m) {
  const info = { sandboxId: m.id, name: m.name, state: m.state, machine: { ...m } };
  if (m.autoSuspendAfterSeconds) info.autoSuspendMs = m.autoSuspendAfterSeconds * 1000;
  if (m.timeoutAt) info.endAt = new Date(m.timeoutAt);
  if (m.archiveAt) info.archiveAt = new Date(m.archiveAt);
  return info;
}
test('raw zero is OFF even when the SDK top-level field is absent', () => {
  const info = sdkInfo(raw());
  assert.equal(info.autoSuspendMs, undefined);
  assert.equal(policyOf(info).idleSeconds, 0);
  assert.equal(verdict(policyOf(info)), 'confirmed');
});
test('a missing raw field is not inferred to be zero', () => {
  const m = raw(); delete m.autoSuspendAfterSeconds;
  assert.equal(verdict(policyOf(sdkInfo(m))), 'unknown');
});
test('explicit raw null means OFF according to the official Machine schema', () => {
  assert.equal(verdict(policyOf(sdkInfo(raw({ autoSuspendAfterSeconds: null })))), 'confirmed');
});
test('invalid false/string raw fields cannot claim OFF', () => {
  for (const x of [false, '0', -1, Infinity, NaN])
    assert.equal(verdict(policyOf(sdkInfo(raw({ autoSuspendAfterSeconds: x })))), 'unknown');
});
test('nonzero, timeout, archive and disagreeing results are not success', () => {
  for (const x of [{ autoSuspendAfterSeconds: 1800 }, { timeoutAt: '2027-01-01T00:00:00Z' }, { archiveAt: '2027-01-01T00:00:00Z' }])
    assert.equal(verdict(policyOf(sdkInfo(raw(x)))), 'needs_action');
  assert.equal(verdict(policyOf(sdkInfo(raw())), policyOf(sdkInfo(raw({autoSuspendAfterSeconds:1800})))), 'conflict');
});
test('older info shapes with no raw object need explicit deadline evidence', () => {
  assert.equal(verdict(policyOf({ autoSuspendMs: 0 })), 'unknown');
  assert.equal(verdict(policyOf({ autoSuspendMs: 0, endAt: null, archiveAt: null })), 'confirmed');
});
test('deadline disagreement between fresh sources cannot show confirmed', () => {
  const off = policyOf(sdkInfo(raw()));
  for (const field of ['timeoutAt', 'archiveAt']) {
    const scheduled = policyOf(sdkInfo(raw({ [field]: '2027-01-01T00:00:00Z' })));
    assert.equal(verdict(off, scheduled), 'conflict');
    assert.equal(verdict(scheduled, off), 'conflict');
    const otherTime = policyOf(sdkInfo(raw({ [field]: '2027-02-01T00:00:00Z' })));
    assert.equal(verdict(scheduled, otherTime), 'conflict');
  }
  assert.equal(verdict(off, policyOf({ autoSuspendMs: 0 })), 'unknown');
});
async function scenario(opts = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ib-policy-'));
  const lines = [], calls = [], answers = [...(opts.answers || [])];
  let machines = (opts.machines || [raw({ autoSuspendAfterSeconds: 1800, timeoutAt: '2027-01-01T00:00:00Z' })]).map(x=>({...x}));
  const deps = {
    home, env: {}, sleep: async()=>{},
    io: { say: s=>lines.push(String(s)), ask: async()=> { if(!answers.length)throw Error('unexpected prompt'); return answers.shift(); } },
    Sandbox: {
      list: async()=>machines.map(sdkInfo),
      connect: async(id, args)=> {
        assert.equal(args.resume, false, 'a check must never auto-resume');
        const m = machines.find(x=>x.id===id);
        return {
          setAutoSuspend: async(n)=> {calls.push(['idle',n]); if(!opts.ignoreWrites)m.autoSuspendAfterSeconds=n/1000;},
          setTimeout: async(n)=> {calls.push(['timeout',n]); if(opts.failTimeout)throw Error('write failed'); if(!opts.ignoreWrites)m.timeoutAt=null; if(opts.timeoutResetsIdle)m.autoSuspendAfterSeconds=1800;},
          getInfo: async()=>sdkInfo(m),
          resume: async()=>{calls.push(['resume']);m.state='running';}
        };
      }
    }
  };
  try { await opts.body({ home, deps, calls, lines, machines }); }
  finally {fs.rmSync(home,{recursive:true,force:true});}
}
test('one-click sets BOTH independent controls and preserves zero readback', async()=> {
  await scenario({body:async({home,deps,calls,lines})=>{
    assert.equal(await run(['apply'],deps),0);
    assert.deepEqual(calls,[['timeout',0],['idle',0]]);
    assert.match(lines.join('\n'),/平台读回已确认/);
    assert.ok(lines.includes('机器名称： example-machine'));
    assert.ok(lines.includes('空闲暂停： 已关闭'));
    assert.ok(lines.includes('到期暂停： 未设置'));
    assert.ok(lines.some(line=>line.startsWith('检查结果： ')));
    const state=JSON.parse(fs.readFileSync(path.join(home,'.config/insta-box/keepalive-state.json')));
    assert.equal(state.result,'confirmed'); assert.equal(state.source,'machine.autoSuspendAfterSeconds');
    assert.equal(fs.statSync(path.join(home,'.config/insta-box/keepalive-state.json')).mode&0o777,0o600);
  }});
});
test('a check is read-only and updates stale cached results', async()=> {
  await scenario({body:async({deps,calls,machines,home})=>{
    await run(['apply'],deps); calls.length=0;
    machines[0].autoSuspendAfterSeconds=1800;
    assert.equal(await run(['check'],deps),2);assert.deepEqual(calls,[]);
    const s=JSON.parse(fs.readFileSync(path.join(home,'.config/insta-box/keepalive-state.json')));
    assert.equal(s.result,'needs_action');
  }});
});
test('a failed fresh list read cannot leave a green confirmed result', async()=> {
  await scenario({ machines: [raw()], body: async({ deps, home }) => {
    const list = deps.Sandbox.list;
    let calls = 0;
    deps.Sandbox.list = async () => {
      if (++calls > 1) throw new Error('temporary read failure');
      return list();
    };
    assert.equal(await run(['check'], deps), 2);
    const state = JSON.parse(fs.readFileSync(path.join(home,'.config/insta-box/keepalive-state.json')));
    assert.equal(state.result, 'unknown');
  }});
});
test('a deadline present only in the list read is surfaced as a conflict', async()=> {
  await scenario({ machines: [raw()], body: async({ deps, home }) => {
    const list = deps.Sandbox.list;
    let calls = 0;
    deps.Sandbox.list = async () => {
      const items = await list();
      if (++calls > 1) items[0] = sdkInfo(raw({ archiveAt: '2027-01-01T00:00:00Z' }));
      return items;
    };
    assert.equal(await run(['check'], deps), 2);
    const state = JSON.parse(fs.readFileSync(path.join(home,'.config/insta-box/keepalive-state.json')));
    assert.equal(state.result, 'conflict');
  }});
});
test('a partial write cannot be marked successful', async()=> {
  await scenario({failTimeout:true,body:async({deps,lines})=>{
    assert.equal(await run(['apply'],deps),2);assert.match(lines.join('\n'),/未完成确认/);
  }});
});
test('HTTP success with ignored fields is detected', async()=>{
  await scenario({ignoreWrites:true,body:async({deps})=>assert.equal(await run(['apply'],deps),2)});
});
test('policy failures and machine names cannot echo either credential type', async()=>{
  await scenario({machines:[raw({name:'ibssh_FAKE_NAME_SECRET'})],body:async({deps,lines})=>{
    deps.Sandbox.connect=async()=>{const e=Error('ibk_FAKE_MESSAGE_SECRET');e.code='ibssh_FAKE_CODE_SECRET';throw e;};
    assert.equal(await run(['check'],deps),1);
    assert.doesNotMatch(lines.join('\n'),/ib(?:k|ssh)_/);
  }});
});
test('multiple machines: choose once, remember selection, modify only target',async()=>{
  await scenario({machines:[raw(),raw({id:'m_two',name:'second-machine',autoSuspendAfterSeconds:1800})],answers:['2'],body:async({deps,machines,lines})=>{
    assert.equal(await run(['apply'],deps),0);
    assert.ok(lines.includes('1. example-machine'));
    assert.ok(lines.includes('2. second-machine'));
    assert.equal(lines.filter(line=>line==='   运行状态： 运行中').length,2);
    assert.equal(machines[0].autoSuspendAfterSeconds,0);
    assert.equal(machines[1].autoSuspendAfterSeconds,0);
    assert.equal(await run(['check'],deps),0);
  }});
});
test('CLI cancellation does not mutate cloud state',async()=>{
  await scenario({machines:[raw(),raw({id:'m_two'})],answers:['0'],body:async({deps,calls})=>{
    assert.equal(await run(['apply'],deps),0);assert.deepEqual(calls,[]);
  }});
});
test('independent archive deadline prevents an all-clear',async()=>{
  await scenario({machines:[raw({archiveAt:'2027-01-01T00:00:00Z'})],body:async({deps,lines})=>{
    assert.equal(await run(['apply'],deps),2);assert.match(lines.join('\n'),/独立停止期限/);
  }});
});

test('absent timeout is not written; idle OFF is the only mutation',async()=>{
  await scenario({machines:[raw({autoSuspendAfterSeconds:1800})],timeoutResetsIdle:true,body:async({deps,calls,home})=>{
    assert.equal(await run(['apply'],deps),0);
    assert.deepEqual(calls,[['idle',0]]);
    const s=JSON.parse(fs.readFileSync(path.join(home,'.config/insta-box/keepalive-state.json')));
    assert.equal(s.writes.timeout,'not-needed');
    assert.deepEqual(s.history.map(x=>x.stage),['before','after-idle','final']);
    assert.deepEqual(s.history.map(x=>x.idleSeconds),[1800,0,0]);
  }});
});
test('timeout update resetting idle cannot overwrite the final OFF mutation',async()=>{
  await scenario({timeoutResetsIdle:true,body:async({deps,calls,home})=>{
    assert.equal(await run(['apply'],deps),0);
    assert.deepEqual(calls,[['timeout',0],['idle',0]]);
    const s=JSON.parse(fs.readFileSync(path.join(home,'.config/insta-box/keepalive-state.json')));
    assert.deepEqual(s.history.map(x=>x.stage),['before','after-timeout','after-idle','final']);
    assert.deepEqual(s.history.map(x=>x.idleSeconds),[1800,1800,0,0]);
  }});
});
test('already healthy machines need no redundant writes',async()=>{
  await scenario({machines:[raw()],timeoutResetsIdle:true,body:async({deps,calls})=>{
    assert.equal(await run(['apply'],deps),0);
    assert.deepEqual(calls,[]);
  }});
});
test('doctor preserves failed write history and never applies settings itself',async()=>{
  await scenario({ignoreWrites:true,body:async({deps,calls,home,lines})=>{
    assert.equal(await run(['apply'],deps),2);
    assert.match(lines.join('\n'),/关闭请求已返回，但云端仍保留 1800/);
    assert.doesNotMatch(lines.join('\n'),/重新执行一键/);
    calls.length=0;
    assert.equal(await run(['doctor'],deps),2);
    assert.deepEqual(calls,[]);
    const s=JSON.parse(fs.readFileSync(path.join(home,'.config/insta-box/keepalive-state.json')));
    assert.equal(s.history[0].stage,'before');
    assert.equal(s.writes.idle,'ok');
    assert.equal(s.result,'needs_action');
    assert.match(lines.join('\n'),/lastApply/);
    assert.match(lines.join('\n'),/"version": "0\.0\.1"/);
    const printed=[], originalLog=console.log;
    console.log=value=>printed.push(String(value));
    try {
      const { io, ...defaultIODeps } = deps;
      assert.equal(await run(['doctor'],defaultIODeps),2);
    } finally { console.log=originalLog; }
    const diagnosis=printed.find(line=>line.startsWith('{'));
    assert.equal(JSON.parse(diagnosis).version,'0.0.1');
    assert.ok(printed.filter(line=>line && line!==diagnosis).every(line=>line.startsWith('  ')));
    assert.ok(printed.some(line=>line.startsWith('  检查结果： ')));
    assert.ok(printed.some(line=>line.startsWith('  提示原因： ')));
    assert.deepEqual(calls,[]);
  }});
});
