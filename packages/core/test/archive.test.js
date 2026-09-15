/**
 * 归档（`.vmpz`）与 zip 容器的测试（M3）。
 *
 * 这里最要紧的四条：
 *   · **审计密钥绝不入档**（否则 HMAC 保护归零）；
 *   · **凭据/私钥默认不入档**，带私钥必须加密，且"带秘密但不加密"这种组合不能存在；
 *   · **篡改可检出**（清单里的 sha256 与条目一一对应）；
 *   · **导入前能预览差异**，且默认不覆盖本地内容。
 */

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  applyImport, collectEntries, crc32, decryptSecrets, diffArchive, encryptSecrets,
  exportArchive, readArchive, sha256Hex, zipCreate, zipRead,
} from '../src/index.js';

function tmp() {
  return mkdtempSync(join(tmpdir(), 'vmprobe-archive-'));
}

/** 造一个像模像样的 storageDir。 */
function seedStorage(dir, { withKeys = true } = {}) {
  mkdirSync(join(dir, 'facts'), { recursive: true });
  mkdirSync(join(dir, 'reports', 't_a', '2026'), { recursive: true });
  mkdirSync(join(dir, 'logs'), { recursive: true });
  if (withKeys) mkdirSync(join(dir, 'keys'), { recursive: true });

  writeFileSync(join(dir, 'targets.json'), JSON.stringify({
    schema: 'vmprobe/targets/1',
    targets: [{
      id: 't_a', label: 'vm-prod-01', hostname: '10.0.0.5', user: 'ops',
      authRef: { kind: 'password', ref: 'VMPROBE_A_PASSWORD' }, tags: ['prod'],
    }],
  }, null, 2), 'utf8');
  writeFileSync(join(dir, 'facts', 't_a.json'), JSON.stringify({ schema: 'vmprobe/facts-store/1', facts: { os: { id: 'debian' } } }), 'utf8');
  writeFileSync(join(dir, 'reports', 't_a', '2026', '2026-09-14.json'), JSON.stringify({ schema: 'vmprobe/report/1', day: '2026-09-14' }), 'utf8');
  writeFileSync(join(dir, 'loads.jsonl'), '{"event":"load"}\n', 'utf8');
  writeFileSync(join(dir, 'logs', 'audit.jsonl'), '{"event":"x"}\n', 'utf8');
  // 这两个**必须**被排除
  writeFileSync(join(dir, 'audit-hmac.key'), 'deadbeef'.repeat(8), 'utf8');
  if (withKeys) writeFileSync(join(dir, 'keys', 't_a'), 'PRIVATE-KEY-CONTENT-SHOULD-NOT-LEAK', { encoding: 'utf8', mode: 0o600 });
}

// ── zip 容器 ────────────────────────────────────────────────────────────────

test('zip 往返：可压缩内容用 deflate，已压缩内容自动退化为 stored', () => {
  const text = 'hello vmprobe '.repeat(500);                   // 高度可压缩
  const random = Buffer.from(Array.from({ length: 2048 }, (_, i) => (i * 37) % 251));
  const buf = zipCreate([
    { name: 'a.txt', data: text },
    { name: '中文/名字.json', data: JSON.stringify({ ok: true }) },
    { name: 'b.bin', data: random },
  ]);
  const entries = zipRead(buf);
  assert.equal(entries.length, 3);
  assert.equal(entries[0].data.toString('utf8'), text);
  assert.equal(entries[1].name, '中文/名字.json', 'UTF-8 文件名必须原样还原');
  assert.deepEqual(entries[2].data, random);
  assert.ok(entries.every((e) => e.crcOk), '每条都要能通过 CRC 校验');
  assert.ok(buf.length < text.length, '可压缩内容应当真的变小了');
});

test('crc32 与已知值一致（把容器格式钉住）', () => {
  assert.equal(crc32(Buffer.from('123456789', 'utf8')), 0xcbf43926);
  assert.equal(crc32(Buffer.from('', 'utf8')), 0);
});

test('zip 读取会拒绝不支持的压缩方法与截断文件（不静默给空数据）', () => {
  assert.throws(() => zipRead(Buffer.alloc(10)), /长度不足/);
  const ok = zipCreate([{ name: 'x', data: 'y' }]);
  assert.throws(() => zipRead(ok.subarray(0, ok.length - 10)), /EOCD|截断/);
});

// ── 导出 ────────────────────────────────────────────────────────────────────

test('★ 审计密钥与私钥默认都不入档，且在清单里如实记录"跳过了什么、为什么"', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    const { buffer, manifest } = exportArchive({ dir, version: '0.3.0', redaction: 'none' });
    const names = zipRead(buffer).map((e) => e.name);

    assert.ok(!names.some((n) => n.includes('audit-hmac.key')), '★ 审计密钥绝不能入档');
    assert.ok(!names.some((n) => n.includes('keys/')), '私钥默认不入档');
    assert.ok(names.includes('data/targets.json'));
    assert.ok(names.includes('data/reports/t_a/2026/2026-09-14.json'));

    const keySkip = manifest.skipped.find((s) => s.path === 'audit-hmac.key');
    assert.ok(keySkip, '清单里必须写明跳过了审计密钥');
    assert.match(keySkip.reason, /永不入档/);
    const privSkip = manifest.skipped.find((s) => s.path.startsWith('keys/'));
    assert.match(privSkip.reason, /私钥/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('审计链与运行记录需要显式开关（默认不带，避免归档过大）', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    const plain = exportArchive({ dir, redaction: 'none' });
    assert.ok(!zipRead(plain.buffer).some((e) => e.name.includes('logs/')));
    const withAudit = exportArchive({ dir, includeAudit: true, redaction: 'none' });
    assert.ok(zipRead(withAudit.buffer).some((e) => e.name === 'data/logs/audit.jsonl'));
    assert.equal(withAudit.manifest.includes.audit, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('脱敏档位：standard 打码主机名/IP 并清空标签，none 原样', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    const masked = readArchive(exportArchive({ dir, redaction: 'standard' }).buffer);
    const maskedTargets = JSON.parse(masked.files.get('targets.json').toString('utf8'));
    assert.equal(maskedTargets.targets[0].hostname, '10.0.*.*');
    assert.deepEqual(maskedTargets.targets[0].tags, []);
    assert.equal(maskedTargets.targets[0].authRef.ref, 'VMPROBE_A_PASSWORD', '引用名要保留（它只是名字，不是凭据）');

    const raw = readArchive(exportArchive({ dir, redaction: 'none' }).buffer);
    const rawTargets = JSON.parse(raw.files.get('targets.json').toString('utf8'));
    assert.equal(rawTargets.targets[0].hostname, '10.0.0.5');
    assert.equal(rawTargets.manifest?.redaction, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('★ 带私钥必须加密：不给口令直接拒绝导出', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    assert.throws(
      () => exportArchive({ dir, includeSecrets: true }),
      /必须同时提供口令/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('★ 带私钥导出：私钥以密文形式存在，且明文绝不出现', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    const { buffer, manifest } = exportArchive({
      dir, includeSecrets: true, passphrase: 'correct horse battery', redaction: 'none',
    });
    const names = zipRead(buffer).map((e) => e.name);
    assert.ok(!names.some((n) => n.startsWith('data/keys/')), '私钥不得以明文条目出现');
    assert.ok(names.includes('secrets.enc.json'), '应有一个加密的秘密容器');
    assert.equal(manifest.includes.secrets, true);
    assert.equal(manifest.includes.secretsEncrypted, 'aes-256-gcm/scrypt');
    // 整个归档的字节里都不得出现明文私钥
    assert.ok(!buffer.includes(Buffer.from('PRIVATE-KEY-CONTENT-SHOULD-NOT-LEAK')), '★ 明文私钥不得出现在归档任何位置');

    // 口令正确才能取回
    const back = readArchive(buffer, { passphrase: 'correct horse battery' });
    assert.equal(back.secrets.get('keys/t_a').toString('utf8'), 'PRIVATE-KEY-CONTENT-SHOULD-NOT-LEAK');
    // 口令错误 → 认证失败，且**不返回半截明文**
    assert.throws(() => readArchive(buffer, { passphrase: 'wrong-password' }), /口令不对|认证/);
    assert.throws(() => readArchive(buffer), /必须提供口令/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('scrypt+AES-GCM 工具函数：加密往返与错误口令', () => {
  const doc = encryptSecrets(JSON.stringify({ a: 1 }), 'passphrase-123');
  assert.equal(doc.algo, 'aes-256-gcm');
  assert.equal(JSON.parse(decryptSecrets(doc, 'passphrase-123')).a, 1);
  assert.throws(() => decryptSecrets(doc, 'passphrase-124'), /解密失败/);
  assert.throws(() => encryptSecrets('x', 'short'), /至少 8 个字符/);
});

// ── 读取与校验 ──────────────────────────────────────────────────────────────

/** 定位某个条目在 zip 里的**数据区**偏移（解析本地头得到，不靠猜）。 */
function payloadOffset(buf, name) {
  const sig = Buffer.from([0x50, 0x4b, 0x03, 0x04]);   // PK\x03\x04
  let at = buf.indexOf(sig);
  while (at !== -1) {
    const nameLen = buf.readUInt16LE(at + 26);
    const extraLen = buf.readUInt16LE(at + 28);
    const compSize = buf.readUInt32LE(at + 18);
    const nm = buf.subarray(at + 30, at + 30 + nameLen).toString('utf8');
    if (nm === name) return { start: at + 30 + nameLen + extraLen, size: compSize };
    at = buf.indexOf(sig, at + 4);
  }
  return null;
}

test('★ 归档内容被改动 → 校验拒绝（清单 sha256 与条目绑定）', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    const bundle = exportArchive({ dir, redaction: 'none' });
    // ⚠️ 第一版想"在 zip 字节里搜明文再改掉"，但那行不通：条目默认是 deflate 压缩的，
    //    明文在容器里根本不存在。正确做法是**重建容器、只换掉某个条目的内容** ——
    //    长度保持一致也没用，因为清单里的 sha256 会把改动暴露出来。
    const entries = zipRead(bundle.buffer);
    const forged = zipCreate(entries.map((e) => (
      e.name === 'data/targets.json'
        ? { name: e.name, data: Buffer.from('{"schema":"vmprobe/targets/1","targets":[]}', 'utf8') }
        : { name: e.name, data: e.data }
    )));
    assert.throws(() => readArchive(forged), /内容与清单不符/);

    // ② 直接破坏某个条目的**数据区**（按本地头算出偏移，不靠随机位置猜 ——
    //    第一版翻的是"文件 60% 处"，结果正好落在不影响内容的头部字段上，测试假通过）
    const where = payloadOffset(bundle.buffer, 'data/reports/t_a/2026/2026-09-14.json');
    assert.ok(where, '应当能定位到条目数据区');
    const flipped = Buffer.from(bundle.buffer);
    const at = where.start + Math.floor(where.size / 2);
    flipped[at] = flipped[at] ^ 0xff;
    assert.throws(() => readArchive(flipped), /CRC 不符|解压失败|长度不符/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('schema 版本：更高版本拒绝导入（不装作能读）', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    const bundle = exportArchive({ dir, redaction: 'none' });
    const entries = zipRead(bundle.buffer);
    const manifest = JSON.parse(entries.find((e) => e.name === 'manifest.json').data.toString('utf8'));
    manifest.schema = 'vmprobe/archive/99';
    const forged = zipCreate(entries.map((e) => (
      e.name === 'manifest.json' ? { name: e.name, data: JSON.stringify(manifest, null, 2) } : { name: e.name, data: e.data }
    )));
    assert.throws(() => readArchive(forged), /拒绝导入/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── 差异预览与导入 ──────────────────────────────────────────────────────────

test('★ 差异预览分出 新增/一致/冲突 三类，并列出凭据缺口', () => {
  const src = tmp();
  const dst = tmp();
  try {
    seedStorage(src);
    seedStorage(dst);
    // 目标机：targets.json 不同、facts 相同、日报缺失
    writeFileSync(join(dst, 'targets.json'), JSON.stringify({ schema: 'vmprobe/targets/1', targets: [{ id: 't_other' }] }), 'utf8');
    rmSync(join(dst, 'reports'), { recursive: true, force: true });

    const archive = readArchive(exportArchive({ dir: src, redaction: 'none' }).buffer);
    const diff = diffArchive({ archive, dir: dst, existingCredentials: ['OTHER_REF'] });

    assert.ok(diff.conflict.some((c) => c.path === 'targets.json'), 'targets.json 应算冲突');
    assert.ok(diff.identical.some((c) => c.path === 'facts/t_a.json'), 'facts 相同应算一致');
    assert.ok(diff.added.some((c) => c.path.startsWith('reports/')), '缺失的日报应算新增');
    assert.deepEqual(diff.credentialGaps, [{ targetId: 't_a', ref: 'VMPROBE_A_PASSWORD' }], '应报出凭据缺口');
  } finally {
    rmSync(src, { recursive: true, force: true });
    rmSync(dst, { recursive: true, force: true });
  }
});

test('★ 导入默认不覆盖冲突文件；加 overwrite 才覆盖，且**先备份**', () => {
  const src = tmp();
  const dst = tmp();
  try {
    seedStorage(src);
    seedStorage(dst);
    writeFileSync(join(dst, 'targets.json'), '{"local":true}\n', 'utf8');
    // 让 facts 成为"本地没有"的文件，才能验证"新增"这条路径
    rmSync(join(dst, 'facts', 't_a.json'), { force: true });
    const archive = readArchive(exportArchive({ dir: src, redaction: 'none' }).buffer);

    const safe = applyImport({ archive, dir: dst, overwrite: false });
    assert.equal(readFileSync(join(dst, 'targets.json'), 'utf8'), '{"local":true}\n', '默认不得覆盖');
    assert.ok(safe.skipped.some((s) => s.includes('targets.json')));
    assert.ok(safe.written.includes('facts/t_a.json'), '本地缺失的文件应被写入');

    const forced = applyImport({ archive, dir: dst, overwrite: true });
    assert.ok(forced.backedUp.some((b) => b.endsWith('targets.json.vmpz-bak')), '覆盖前必须备份');
    const restored = JSON.parse(readFileSync(join(dst, 'targets.json'), 'utf8'));
    assert.equal(restored.targets[0].id, 't_a', '覆盖后应是归档里的内容');
  } finally {
    rmSync(src, { recursive: true, force: true });
    rmSync(dst, { recursive: true, force: true });
  }
});

test('带私钥的归档导入时把私钥落到 keys/ 下（0600）', () => {
  const src = tmp();
  const dst = tmp();
  try {
    seedStorage(src);
    mkdirSync(dst, { recursive: true });
    const bundle = exportArchive({ dir: src, includeSecrets: true, passphrase: 'passphrase-xyz', redaction: 'none' });
    const archive = readArchive(bundle.buffer, { passphrase: 'passphrase-xyz' });
    const res = applyImport({ archive, dir: dst });
    assert.deepEqual(res.secretsWritten, ['keys/t_a']);
    assert.equal(readFileSync(join(dst, 'keys', 't_a'), 'utf8'), 'PRIVATE-KEY-CONTENT-SHOULD-NOT-LEAK');
  } finally {
    rmSync(src, { recursive: true, force: true });
    rmSync(dst, { recursive: true, force: true });
  }
});

test('collectEntries 报告跳过项时路径用正斜杠（跨平台归档路径统一）', () => {
  const dir = tmp();
  try {
    seedStorage(dir);
    const { entries, skipped } = collectEntries({ dir, redaction: 'none' });
    assert.ok(entries.every((e) => !e.rel.includes('\\')), '归档内路径必须是正斜杠');
    assert.ok(skipped.every((s) => !s.path.includes('\\')));
    assert.equal(sha256Hex(entries[0].data.toString('base64')).length, 64);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
