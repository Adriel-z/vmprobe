/**
 * 审计链 HMAC 加固的测试（M5）。
 *
 * 这里要同时守住**两件相反方向的事**：
 *   · 加了密钥之后，"重算整条链"不再能伪造（这是 HMAC 的全部意义）；
 *   · **旧的无密钥链必须照旧能验**（不能因为有新机制就把历史宣布为损坏）。
 * 另外还要守住一条最容易写错的东西：**换密钥 ≠ 被篡改**，报错必须区分这两者。
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ALGO_HMAC, ALGO_SHA256, GENESIS, canonicalJson, chainRecord, createAuditLog,
  generateAuditKey, hashRecord, keyIdOf, sha256Hex, verifyChain,
} from '../src/index.js';

/** 造一条链。`keyByIndex` 返回该条使用的密钥（null = 旧格式）。 */
function buildChain(count, keyByIndex = () => null) {
  const records = [];
  let prev = GENESIS;
  for (let i = 0; i < count; i += 1) {
    const rec = chainRecord(prev, { seq: i, event: 'x', value: i * 10 }, keyByIndex(i));
    records.push(rec);
    prev = rec.hash;
  }
  return records;
}

test('旧格式（无密钥）链照旧可验，且如实说明"不抗伪造"', () => {
  const chain = buildChain(5);
  const v = verifyChain(chain);
  assert.equal(v.ok, true);
  assert.equal(v.forgeryResistant, false, '无密钥链不能声称抗伪造');
  assert.equal(v.hmacCount, 0);
  assert.equal(v.legacyCount, 5);
  // 旧记录的 canonical 正文里不该凭空多出 algo/keyId 字段（否则旧链全废）
  assert.equal('algo' in chain[0], false);
  assert.equal('keyId' in chain[0], false);
});

test('有密钥时逐条带 algo/keyId，整链抗伪造', () => {
  const key = generateAuditKey();
  const chain = buildChain(4, () => key);
  const v = verifyChain(chain, GENESIS, { key });
  assert.equal(v.ok, true);
  assert.equal(v.hmacCount, 4);
  assert.equal(v.legacyCount, 0);
  assert.equal(v.forgeryResistant, true);
  assert.equal(chain[0].algo, ALGO_HMAC);
  assert.equal(chain[0].keyId, keyIdOf(key));
  // keyId 是密钥的哈希前缀，**不是**密钥本身（不能反过来推出密钥）
  assert.notEqual(chain[0].keyId, key);
  assert.equal(chain[0].keyId.length, 16);
});

test('★ 没有密钥就验不了 hmac 链 —— 报"缺密钥"而不是"被篡改"', () => {
  const key = generateAuditKey();
  const chain = buildChain(3, () => key);
  const v = verifyChain(chain);
  assert.equal(v.ok, false);
  assert.equal(v.keyMissingAt, 0);
  assert.match(v.reason, /没有提供密钥/);
  assert.ok(!/改动/.test(v.reason), '缺密钥不是"内容被改动"，两者必须分清');
});

test('★ 错密钥 → 报"密钥不符"（不等于被篡改）', () => {
  const key = generateAuditKey();
  const other = generateAuditKey();
  const chain = buildChain(3, () => key);
  const v = verifyChain(chain, GENESIS, { key: other });
  assert.equal(v.ok, false);
  assert.equal(v.keyMismatchAt, 0);
  assert.match(v.reason, /无法校验/);
  assert.match(v.reason, /不等于/);
});

test('★ 有密钥时，篡改内容可检出', () => {
  const key = generateAuditKey();
  const chain = buildChain(4, () => key);
  chain[2] = { ...chain[2], value: 999 };
  const v = verifyChain(chain, GENESIS, { key });
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 2);
  assert.match(v.reason, /内容被改动/);
});

test('★ 攻击者"改 algo 再重算"不行 —— algo 与 keyId 都在哈希正文里', () => {
  const key = generateAuditKey();
  const chain = buildChain(3, () => key);
  // 攻击者拿到写权限但没有密钥：把第 1 条降级成无密钥格式并重算
  const forged = { ...chain[1] };
  delete forged.algo;
  delete forged.keyId;
  delete forged.hash;
  const recomputed = { ...forged, prev: chain[0].hash, hash: hashRecord(chain[0].hash, forged, null, ALGO_SHA256) };
  assert.notEqual(recomputed.hash, chain[1].hash, '改了 algo 的正文，哈希必然不同');
  const chain2 = [chain[0], recomputed, chain[2]];
  const v = verifyChain(chain2, GENESIS, { key });
  assert.equal(v.ok, false);
  assert.equal(v.downgradeAt, 1, '必须报"降级"');
  assert.match(v.reason, /不允许降级/);
});

test('★ 整链降级重写：**链自身无法识别**（诚实交代），但可用 requireHmac 检出', () => {
  const key = generateAuditKey();
  const chain = buildChain(3, () => key);
  // 攻击者有写权限但没有密钥：把整条链重算成无密钥（旧）格式 —— 自洽
  const rebuilt = [];
  let prev = GENESIS;
  for (const rec of chain) {
    const body = { ...rec };
    delete body.prev; delete body.hash; delete body.algo; delete body.keyId;
    const next = { ...body, prev, hash: hashRecord(prev, body, null, ALGO_SHA256) };
    rebuilt.push(next);
    prev = next.hash;
  }

  // ① 默认判定：这条链"自洽"，看起来就是一条普通的旧格式链 —— 这是 HMAC 的**真实边界**
  const lax = verifyChain(rebuilt, GENESIS, { key });
  assert.equal(lax.ok, true, '整段重写后链是自洽的，链自身无从分辨');
  assert.equal(lax.hmacCount, 0);
  assert.equal(lax.forgeryResistant, false, '但绝不会声称它抗伪造');

  // ② 调用方明确知道"本机启用过密钥"时，可以要求链里必须有 hmac 记录
  const strict = verifyChain(rebuilt, GENESIS, { key, requireHmac: true });
  assert.equal(strict.ok, false);
  assert.equal(strict.unkeyedEntirely, true);
  assert.match(strict.reason, /没有任何 hmac/);
  assert.match(strict.reason, /无法区分/);

  // ③ 真的旧历史（本就没启用过密钥）不该被误报 —— 默认判定下 ok
  const legacyOnly = buildChain(2);
  assert.equal(verifyChain(legacyOnly, GENESIS, {}).ok, true);
  assert.equal(verifyChain(legacyOnly, GENESIS, { requireHmac: true }).unkeyedEntirely, true);
});

test('混合链（旧段 + 新段）可验，且如实标注"非全链抗伪造"', () => {
  const key = generateAuditKey();
  const chain = buildChain(5, (i) => (i < 2 ? null : key));
  const v = verifyChain(chain, GENESIS, { key });
  assert.equal(v.ok, true);
  assert.equal(v.legacyCount, 2);
  assert.equal(v.hmacCount, 3);
  assert.equal(v.forgeryResistant, false, '混有旧记录时不能声称全链抗伪造');
});

test('createAuditLog：带密钥时新记录自动 HMAC，装载历史不受影响', () => {
  const key = generateAuditKey();
  const legacy = buildChain(2);                       // 先有一小段旧格式历史
  const log = createAuditLog({ key, maxRecords: 100 });
  log.hydrate(legacy);
  const fresh = log.append({ event: 'new' });
  assert.equal(fresh.algo, ALGO_HMAC);
  const v = log.verify();
  assert.equal(v.ok, true, '旧段 + 新段要能一起验');
  assert.equal(v.legacyCount, 2);
  assert.equal(v.hmacCount, 1);
  assert.equal(v.keyId, keyIdOf(key));
  assert.equal(v.keyed, true);
});

test('★ setKey 在已有 hmac 记录时拒绝换密钥（否则旧记录将无法校验）', () => {
  const key = generateAuditKey();
  const other = generateAuditKey();
  const log = createAuditLog({ key });
  log.append({ event: 'a' });
  const res = log.setKey(other);
  assert.equal(res.ok, false);
  assert.match(res.reason, /轮换/);
  assert.equal(log.keyId, keyIdOf(key), '拒绝之后密钥保持不变');

  // 链里还没有 hmac 记录时（一开始就没密钥）允许设置
  const log2 = createAuditLog({});
  log2.append({ event: 'legacy' });
  assert.equal(log2.setKey(other).ok, true);
  assert.equal(log2.verify().ok, true);
});

test('canonicalJson 对键序不敏感（哈希可比性的基础）', () => {
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
});

test('hashRecord 的 algo 参数决定算法，且缺密钥时明确抛错', () => {
  const key = generateAuditKey();
  const body = { x: 1 };
  const hmac = hashRecord(GENESIS, body, key, ALGO_HMAC);
  const plain = hashRecord(GENESIS, body, null, ALGO_SHA256);
  assert.notEqual(hmac, plain);
  assert.equal(plain, sha256Hex(`${GENESIS}\n${canonicalJson(body)}`), '旧格式必须与旧实现逐字节一致');
  assert.throws(() => hashRecord(GENESIS, body, null, ALGO_HMAC), /未提供密钥/);
});
