#!/usr/bin/env node
// Author: Pre
// Zero is a valid OFF value. SDK 0.2.0/0.5.3 toInfo() omits it;
// read info.machine.autoSuspendAfterSeconds, not its truthiness.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';

export const VERSION = '0.0.1';
const own = (o, k) => o != null && Object.hasOwn(o, k);
const number = v => typeof v === 'number' && Number.isFinite(v) && v >= 0;
const clean = v => String(v ?? '').replace(/ib(?:k|ssh)_[a-zA-Z0-9._~+/=%-]+/g, '[已隐藏]')
  .replace(/[\x00-\x1f\x7f-\x9f]/g, '').slice(0, 160);

export function policyOf(info) {
  const raw = info?.machine;
  let idle = null, source = 'missing';
  if (own(raw, 'autoSuspendAfterSeconds')) {
    // The official Machine schema also defines explicit JSON null as OFF.
    if (raw.autoSuspendAfterSeconds === null) idle = 0;
    else if (number(raw.autoSuspendAfterSeconds)) idle = raw.autoSuspendAfterSeconds;
    source = 'machine.autoSuspendAfterSeconds';
  } else if (own(info, 'autoSuspendMs')) {
    if (number(info.autoSuspendMs)) idle = info.autoSuspendMs / 1000;
    source = 'autoSuspendMs';
  }
  function deadline(rawKey, sdkKey) {
    const known = own(raw, rawKey) || own(info, sdkKey) || (raw && typeof raw.id === 'string');
    const value = own(raw, rawKey) ? raw[rawKey] : info?.[sdkKey];
    // The documented machine schema omits empty optional deadlines.
    if (known && (value == null || value === '')) return { state: 'none', at: null };
    if (value != null && Number.isFinite(new Date(value).getTime()))
      return { state: 'set', at: new Date(value).toISOString() };
    return { state: 'unknown', at: null };
  }
  return { idleSeconds: idle, source,
    timeout: deadline('timeoutAt', 'endAt'), archive: deadline('archiveAt', 'archiveAt') };
}
export function verdict(p, other, writesFailed = false) {
  if (writesFailed) return 'error';
  if (other && p.idleSeconds !== null && other.idleSeconds !== null &&
      p.idleSeconds !== other.idleSeconds) return 'conflict';
  for (const field of ['timeout', 'archive']) {
    if (other && p[field].state !== 'unknown' && other[field].state !== 'unknown' &&
        (p[field].state !== other[field].state || p[field].at !== other[field].at)) return 'conflict';
  }
  const observations = other ? [p, other] : [p];
  if (observations.some(x => (x.idleSeconds !== null && x.idleSeconds !== 0) ||
      x.timeout.state === 'set' || x.archive.state === 'set'))
    return 'needs_action';
  if (observations.every(x => x.idleSeconds === 0 && x.timeout.state === 'none' &&
      x.archive.state === 'none')) return 'confirmed';
  return 'unknown';
}
function privateDir(dir) {
  if (fs.existsSync(dir) && fs.lstatSync(dir).isSymbolicLink()) throw new Error('配置目录不能是符号链接');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
}
function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}
export function atomicJSON(file, data) {
  privateDir(path.dirname(file));
  const tmp = file + '.' + process.pid + '.tmp';
  try {
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, file);
  } finally { if (fs.existsSync(tmp)) fs.unlinkSync(tmp); }
}
function errText(e, key = '') {
  const code = e?.code || '';
  if (e?.status === 401) return 'API Key 已失效；运行 ibt key set 更换。';
  if (e?.status === 403) return '平台拒绝此操作：请核对 machines:write 权限及账号允许的生命周期策略（ibt cloud account）。';
  if (e?.status === 429) return '平台请求额度受限，请稍后重试。';
  if (e?.status === 409) return '机器正执行其他操作，请稍后重试。';
  let msg = clean(e?.message || '平台请求失败');
  if (key) msg = msg.split(key).join('[已隐藏]');
  msg = msg.replace(/ibk_[a-zA-Z0-9_-]+/g, '[已隐藏]');
  return (code ? clean(code) + '：' : '') + msg;
}
function makeTTY() {
  let input, rl;
  return {
    say: value => console.log(String(value).split('\n').map(line => line ? '  ' + line : '').join('\n')),
    raw: value => console.log(value),
    async ask(prompt) {
      if (!rl) {
        input = fs.createReadStream('/dev/tty');
        rl = createInterface({ input, output: process.stdout, terminal: true });
      }
      return (await rl.question('  ' + prompt)).trim();
    },
    close() { rl?.close(); input?.destroy(); }
  };
}

export async function run(args = [], deps = {}) {
  const home = deps.home || os.homedir(), env = deps.env || process.env;
  const io = deps.io || makeTTY();
  const cfg = path.join(home, '.config/insta-box');
  const selectionFile = path.join(cfg, 'machine.json');
  const cacheFile = path.join(cfg, 'keepalive-state.json');
  const cmd = args[0] || 'check', target = args[1] || '';
  const key = env.INSTABOX_API_KEY || '';
  const pause = deps.sleep || (ms => new Promise(r => setTimeout(r, ms)));
  const options = { apiUrl: 'https://api.instabox.sh', requestTimeoutMs: 15000, operationTimeoutMs: 120000, ...deps.sdkOptions };
  const labels = { running: '运行中', suspended: '已暂停', paused: '已暂停', stopped: '已停止' };
  let selected;
  const safeName = m => clean(m.name || m.sandboxId);
  const statusName = m => labels[m.state] || clean(m.state || '未知');
  function storeSelection(m) {
    const previous = readJSON(selectionFile);
    atomicJSON(selectionFile, { sandboxId: m.sandboxId, name: safeName(m) });
    // A changed target must never inherit another machine's green status.
    if (previous.sandboxId && previous.sandboxId !== m.sandboxId && fs.existsSync(cacheFile)) fs.unlinkSync(cacheFile);
  }
  try {
    const allowed = ['apply', 'check', 'status', 'resume', 'machines', 'auth', 'doctor'];
    if (!allowed.includes(cmd)) throw new Error('未知操作：' + clean(cmd));
    const { Sandbox } = deps.Sandbox ? deps : await import('@insforge/instabox-sdk');
    const list = await Sandbox.list(options);
    if (!Array.isArray(list)) throw new Error('机器列表格式异常，已停止。');
    if (cmd === 'auth') { io.say('授权有效。'); return 0; }
    if (list.length === 0) throw new Error('账号中没有可管理的机器。');
    const last = readJSON(selectionFile);
    if (target) {
      const matches = list.filter(m => m.name === target || m.sandboxId === target);
      if (matches.length !== 1) throw new Error('未找到唯一的目标机器。');
      selected = matches[0];
    } else if (list.length === 1) selected = list[0];
    else if (cmd !== 'machines') selected = list.find(m => m.sandboxId === last.sandboxId);
    if (!selected) {
      io.say('选择要管理的机器：');
      list.forEach((m, i) => {
        io.say(`${i + 1}. ${safeName(m)}`);
        io.say(`   运行状态： ${statusName(m)}`);
      });
      while (!selected) {
        const n = await io.ask('序号 [0 返回]：');
        if (n === '' || n === '0') return 0;
        if (/^[1-9][0-9]*$/.test(n) && +n <= list.length) selected = list[+n - 1];
        else io.say('请输入列表中的序号。');
      }
    }
    storeSelection(selected);
    if (cmd === 'machines') { io.say('已选择：' + safeName(selected)); return 0; }
    const box = await Sandbox.connect(selected.sandboxId, { ...options, resume: false });
    if (cmd === 'resume') {
      if (selected.state === 'running') io.say('机器已经在运行。');
      else {
        if (!target && await io.ask('恢复 ' + safeName(selected) + '？[y/N]：') !== 'y') return 0;
        await box.resume(); io.say('机器已恢复。');
      }
      return 0;
    }
    const writes = {}, errors = [], history = [];
    async function observe(stage) {
      try {
        const current = await box.getInfo();
        const policy = policyOf(current);
        history.push({ stage, idleSeconds: policy.idleSeconds,
          timeout: policy.timeout.state, archive: policy.archive.state });
        return current;
      } catch (e) {
        history.push({ stage, read: 'failed' });
        errors.push(errText(e, key));
        return null;
      }
    }
    if (cmd === 'apply') {
      io.say('正在配置 ' + safeName(selected) + '…');
      const before = await observe('before');
      const initial = policyOf(before);
      // Do not send a redundant timeout PATCH. Some deployments may reapply an
      // idle default when another lifecycle field is updated. Clear a real
      // deadline first, and always make the idle-policy write the LAST mutation.
      if (initial.timeout.state === 'none') writes.timeout = 'not-needed';
      else {
        try { await box.setTimeout(0); writes.timeout = 'ok'; }
        catch (e) { writes.timeout = 'failed'; errors.push(errText(e, key)); }
        await observe('after-timeout');
      }
      if (initial.idleSeconds === 0 && writes.timeout === 'not-needed') writes.idle = 'not-needed';
      else {
        try { await box.setAutoSuspend(0); writes.idle = 'ok'; }
        catch (e) { writes.idle = 'failed'; errors.push(errText(e, key)); }
        await observe('after-idle');
      }
    }
    let info, peer, result, p;
    const attempts = cmd === 'apply' ? 3 : 1;
    for (let i = 0; i < attempts; i++) {
      try { info = await box.getInfo(); }
      catch (e) { errors.push(errText(e, key)); info = null; }
      try {
        const refreshed = await Sandbox.list(options);
        peer = refreshed.find(m => m.sandboxId === selected.sandboxId);
      } catch (e) { errors.push(errText(e, key)); peer = null; }
      // Both are fresh GET results. The raw machine survives the SDK mapping.
      const chosenInfo = info || peer;
      p = policyOf(chosenInfo);
      result = verdict(p, info && peer ? policyOf(peer) : null, Object.values(writes).includes('failed'));
      if (result === 'confirmed' && (!info || !peer)) result = 'unknown';
      if (result === 'confirmed' || i === attempts - 1 || Object.values(writes).includes('failed')) break;
      await pause(1000);
    }
    const checkedAt = new Date().toISOString();
    const record = { schema: 2, sandboxId: selected.sandboxId, name: safeName(selected), checkedAt,
      result, idleSeconds: p.idleSeconds, timeout: p.timeout, archive: p.archive,
      source: p.source, writes, history, machineState: info?.state || peer?.state || selected.state };
    if (cmd === 'apply') record.history.push({ stage: 'final', idleSeconds: p.idleSeconds,
      timeout: p.timeout.state, archive: p.archive.state });
    if (cmd === 'apply') record.requestedAt = checkedAt;
    else {
      const old = readJSON(cacheFile);
      if (old.sandboxId === selected.sandboxId) {
        if (old.requestedAt) record.requestedAt = old.requestedAt;
        // Keep the last mutation evidence when a read-only check is performed.
        record.writes = old.writes || {};
        record.history = Array.isArray(old.history) ? old.history : [];
      }
    }
    atomicJSON(cacheFile, record);
    io.say('');
    io.say('机器名称： ' + safeName(selected));
    io.say('空闲暂停： ' + (p.idleSeconds === 0 ? '已关闭' : p.idleSeconds === null ? '无法读取' : `${p.idleSeconds} 秒后暂停`));
    io.say('到期暂停： ' + (p.timeout.state === 'none' ? '未设置' : p.timeout.at || '无法读取'));
    if (p.archive.state !== 'none') io.say('到期停止： ' + (p.archive.at || '无法读取'));
    if (result === 'confirmed') {
      io.say(cmd === 'apply' ? '检查结果： 防休眠配置完成（平台读回已确认）' : '检查结果： 防休眠已配置（平台读回已确认）');
      if ((info?.state || selected.state) !== 'running') io.say('后续操作： 机器仍未运行，请在机器管理中恢复。');
    } else {
      io.say('检查结果： 未完成确认，不会标记为成功');
      if (p.archive.state === 'set') io.say('提示原因： 存在独立停止期限；请先在平台取消该期限。');
      else if (errors.length) io.say('提示原因： ' + [...new Set(errors)].join('；'));
      else if (result === 'conflict') io.say('提示原因： 两次读取的空闲暂停或到期策略不一致。');
      else if (result === 'needs_action') {
        if (p.idleSeconds !== null && p.idleSeconds > 0 && cmd === 'apply' && writes.idle === 'ok') {
          io.say('提示原因： 关闭请求已返回，但云端仍保留 ' + p.idleSeconds + ' 秒的空闲暂停规则。');
          io.say('后续操作： ibt cloud account 查看账号策略；可用 ibt keepalive setup 配置 API 保活。');
        } else io.say('提示原因： 仍有暂停/停止规则；可运行 ibt keepalive apply 配置。');
      }
      else io.say('后续操作： 运行 ibt doctor 可查看精简诊断，无需重装节点。');
    }
    if (cmd === 'doctor') {
      // Explicit allow-list: never print raw machine objects, metadata, addresses or credentials.
      io.say('');
      const diagnosis = JSON.stringify({ version: VERSION, source: p.source, idleSeconds: p.idleSeconds,
        timeout: p.timeout.state, archive: p.archive.state, result,
        sdkField: typeof (info || peer)?.autoSuspendMs,
        rawField: typeof (info || peer)?.machine?.autoSuspendAfterSeconds,
        lastWrites: record.writes, lastApply: record.history }, null, 2);
      if (io.raw) io.raw(diagnosis); else io.say(diagnosis);
    }
    return result === 'confirmed' ? 0 : 2;
  } catch (e) {
    if (selected) atomicJSON(cacheFile, { schema: 2, sandboxId: selected.sandboxId, name: safeName(selected),
      checkedAt: new Date().toISOString(), result: 'error' });
    io.say('[失败] ' + errText(e, key));
    return 1;
  } finally { if (!deps.io) io.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  process.exitCode = await run(process.argv.slice(2));
