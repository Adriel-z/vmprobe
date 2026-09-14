/**
 * 审计哈希链单测 —— 重点是「篡改必被检出」这条可验证的安全属性。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  GENESIS,
  canonicalJson,
  chainRecord,
  createAuditLog,
  hashRecord,
  tailHash,
  verifyChain,
} from '../src/audit.js';

function sampleRun(i) {
  return {
    runId: `r_${i}`,
    action: 'system.update',
    risk: 'R2',
    resolvedArgv: [['apt-get', '-y', 'dist-upgrade']],
    exit: 0,
  };
}

test('规范化 JSON 与键顺序无关（保证跨平台哈希一致）', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), canonicalJson({ a: 2, b: 1 }));
  assert.equal(canonicalJson({ a: 2, b: 1 }), '{"a":2,"b":1}');
  assert.deepEqual(canonicalJson([1, 'x', null]), '[1,"x",null]');
});

test('链首 prev 为 GENESIS', () => {
  const rec = chainRecord(GENESIS, sampleRun(1));
  assert.equal(rec.prev, GENESIS);
  assert.equal(rec.hash.length, 64);
  assert.equal(verifyChain([rec]).ok, true);
});

test('完整链可校验，长度正确', () => {
  const log = createAuditLog();
  for (let i = 0; i < 5; i++) log.append(sampleRun(i));
  assert.equal(log.length, 5);
  const v = log.verify();
  assert.equal(v.ok, true);
  assert.equal(v.length, 5);
  assert.equal(v.truncated, 0, '未触发上限时不应有裁剪');
  assert.equal(v.total, 5);
});

test('篡改中间记录的内容 → 在该点断链', () => {
  const log = createAuditLog();
  for (let i = 0; i < 4; i++) log.append(sampleRun(i));
  const snap = log.snapshot();

  snap[1].exit = 1; // 把「成功」改成「失败」，试图掩盖一次失败执行
  const v = verifyChain(snap);
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 1);
  assert.match(v.reason, /内容被改动/);
});

test('删除一条记录 → 后续 prev 不匹配，断链被检出', () => {
  const log = createAuditLog();
  for (let i = 0; i < 4; i++) log.append(sampleRun(i));
  const snap = log.snapshot();

  snap.splice(2, 1);
  const v = verifyChain(snap);
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 2);
  assert.match(v.reason, /prev 不匹配/);
});

test('替换整条记录（连同重算自身 hash）仍会被检出', () => {
  const log = createAuditLog();
  for (let i = 0; i < 3; i++) log.append(sampleRun(i));
  const snap = log.snapshot();

  // 攻击者很聪明：他改内容后自己也重算了第 1 条的 hash
  const forgedBody = { ...snap[1], runId: 'r_forged' };
  delete forgedBody.prev;
  delete forgedBody.hash;
  snap[1] = { ...forgedBody, prev: snap[0].hash, hash: hashRecord(snap[0].hash, forgedBody) };

  const v = verifyChain(snap);
  assert.equal(v.ok, false, '第 2 条自身自洽了，但第 3 条的 prev 指向旧 hash');
  assert.equal(v.brokenAt, 2);
});

test('原子性：chainRecord 不修改入参', () => {
  const original = sampleRun(1);
  const frozenCopy = JSON.parse(JSON.stringify(original));
  chainRecord(GENESIS, original);
  assert.deepEqual(original, frozenCopy, 'chainRecord 不应污染调用方对象');
});

test('tailHash 空集返回 GENESIS', () => {
  assert.equal(tailHash([]), GENESIS);
  const log = createAuditLog();
  const a = log.append(sampleRun(1));
  assert.equal(tailHash(log.snapshot()), a.hash);
});

test('append 自动补 ts，且 ts 进哈希', () => {
  const log = createAuditLog();
  const rec = log.append({ action: 'probe.facts' });
  assert.ok(rec.ts, '应自动补时间戳');
  const snap = log.snapshot();
  snap[0].ts = '1999-01-01T00:00:00.000Z';
  assert.equal(verifyChain(snap).ok, false, '改时间戳也必须断链');
});

test('非有限数值被拒绝，避免 NaN 造成哈希不一致', () => {
  assert.throws(() => canonicalJson({ x: Number.NaN }), /非有限数值/);
  assert.throws(() => canonicalJson({ x: Infinity }), /非有限数值/);
});
