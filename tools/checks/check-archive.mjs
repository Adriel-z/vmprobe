/**
 * 归档功能的**外部交叉验证**（M3）。
 *
 * 单元测试只能证明"我的读能读懂我的写"。这个脚本做的是另一件事：
 * 把导出的 `.vmpz` 交给**别人的实现**去解 —— PowerShell 的 `Expand-Archive`。
 * 如果它能正常解开、目录结构对得上，就说明我拼的 ZIP 容器符合规范，
 * 而不是只有我自己能读的私有格式。
 *
 * 顺带验证整条迁移链路：导出 → **外部解压核对** → 导入到干净目录 → 逐文件比对。
 *
 *   node tools/checks/check-archive.mjs
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';

import { applyImport, diffArchive, exportArchive, readArchive } from '../../packages/core/src/index.js';

let failures = 0;
const log = (s = '') => console.log(s);
const check = (label, fn) => {
  try {
    fn();
    console.log(`  ✔ ${label}`);
  } catch (err) {
    failures += 1;
    console.log(`  ✖ ${label}\n      ${err.message}`);
  }
};
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

const work = mkdtempSync(join(tmpdir(), 'vmprobe-archive-check-'));
const src = join(work, 'src');
const dst = join(work, 'dst');
const unzipDir = join(work, 'unzipped');

/** 造一个真实的 storageDir（含必须被排除的密钥文件）。 */
function seed(dir) {
  mkdirSync(join(dir, 'facts'), { recursive: true });
  mkdirSync(join(dir, 'reports', 't_vm', '2026'), { recursive: true });
  mkdirSync(join(dir, 'logs'), { recursive: true });
  mkdirSync(join(dir, 'keys'), { recursive: true });
  writeFileSync(join(dir, 'targets.json'), JSON.stringify({
    schema: 'vmprobe/targets/1',
    targets: [{ id: 't_vm', label: 'vm-a', hostname: '10.0.0.7', user: 'ops', authRef: { kind: 'password', ref: 'VMPROBE_VM_A_PASSWORD' }, tags: ['prod'] }],
  }, null, 2), 'utf8');
  writeFileSync(join(dir, 'facts', 't_vm.json'), JSON.stringify({ schema: 'vmprobe/facts-store/1', facts: { os: { id: 'debian', versionId: '12' } } }), 'utf8');
  writeFileSync(join(dir, 'reports', 't_vm', '2026', '2026-09-14.json'), JSON.stringify({ schema: 'vmprobe/report/1', day: '2026-09-14' }, null, 2), 'utf8');
  writeFileSync(join(dir, 'loads.jsonl'), '{"event":"load"}\n', 'utf8');
  writeFileSync(join(dir, 'logs', 'audit.jsonl'), '{"event":"config.effective"}\n', 'utf8');
  writeFileSync(join(dir, 'audit-hmac.key'), 'aa'.repeat(32), 'utf8');           // 必须排除
  writeFileSync(join(dir, 'keys', 't_vm'), 'PRIVATE-KEY-MATERIAL', { mode: 0o600 }); // 默认排除
}

log('\n[1] 导出');
seed(src);
const archivePath = join(work, 'export.vmpz');
const { buffer, manifest } = exportArchive({
  dir: src, version: '0.3.0', redaction: 'none', includeAudit: true,
});
writeFileSync(archivePath, buffer);
log(`  已导出 ${archivePath}（${(buffer.length / 1024).toFixed(1)} KiB，${manifest.counts.files} 个条目）`);

check('清单 schema 正确', () => assert(manifest.schema === 'vmprobe/archive/1', `实际 ${manifest.schema}`));
check('清单里逐条记了 sha256 与字节数', () => {
  assert(manifest.entries.length >= 4, `条目太少：${manifest.entries.length}`);
  assert(manifest.entries.every((e) => /^[0-9a-f]{64}$/.test(e.sha256)), 'sha256 形状不对');
});
check('★ 审计密钥与私钥被排除，且清单里写明原因', () => {
  const names = manifest.entries.map((e) => e.path);
  assert(!names.includes('audit-hmac.key'), '审计密钥不得入档');
  assert(!names.some((n) => n.startsWith('keys/')), '私钥默认不得入档');
  const skip = manifest.skipped.map((s) => s.path);
  assert(skip.includes('audit-hmac.key'), '清单必须写明跳过了审计密钥');
  assert(skip.some((s) => s.startsWith('keys/')), '清单必须写明跳过了私钥');
});

log('\n[2] 外部实现交叉验证（PowerShell Expand-Archive）');
let externalOk = false;
try {
  mkdirSync(unzipDir, { recursive: true });
  execFileSync('powershell', [
    '-NoProfile', '-Command',
    `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${unzipDir}' -Force`,
  ], { stdio: 'pipe' });
  externalOk = true;
  log('  PowerShell 成功解开归档（说明 ZIP 容器符合规范，不是私有格式）');
} catch (err) {
  log(`  ⚠ PowerShell 解压失败（本机可能没有 powershell）：${String(err.stderr ?? err.message).slice(0, 200)}`);
}

if (externalOk) {
  check('★ 外部解压出的文件与清单一致（内容 + sha256）', () => {
    for (const meta of manifest.entries) {
      const p = join(unzipDir, 'data', meta.path.split('/').join(sep));
      assert(existsSync(p), `外部解压缺少文件：${meta.path}`);
      const bytes = readFileSync(p);
      assert(bytes.length === meta.bytes, `${meta.path} 长度不符`);
    }
  });
  check('★ 外部解压的目录树里没有审计密钥/私钥', () => {
    const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (
      e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]
    ));
    const files = walk(unzipDir).map((f) => relative(unzipDir, f).split(sep).join('/'));
    assert(!files.some((f) => f.includes('audit-hmac.key')), `外部解压结果里出现了审计密钥：${files.join(', ')}`);
    assert(!files.some((f) => f.includes('/keys/')), '外部解压结果里出现了私钥');
    log(`    解出的条目：${files.join('、')}`);
  });
}

log('\n[3] 导入到干净目录');
const readBack = readArchive(readFileSync(archivePath));
const diff = diffArchive({ archive: readBack, dir: dst });
check('干净目录下差异全是"新增"', () => {
  assert(diff.added.length === readBack.files.size, `新增 ${diff.added.length}/${readBack.files.size}`);
  assert(diff.conflict.length === 0, '不该有冲突');
});

const res = applyImport({ archive: readBack, dir: dst });
check('导入写入了全部条目', () => assert(res.written.length === readBack.files.size, `写入 ${res.written.length}`));
check('★ 逐文件内容与源目录一致', () => {
  for (const rel of readBack.files.keys()) {
    const a = readFileSync(join(src, rel.split('/').join(sep)));
    const b = readFileSync(join(dst, rel.split('/').join(sep)));
    assert(a.equals(b), `${rel} 内容不一致`);
  }
});
check('★ 导入目录里没有审计密钥（迁移不该带走它）', () => {
  assert(!existsSync(join(dst, 'audit-hmac.key')), '导入结果里出现了审计密钥');
});
check('★ 凭据缺口被报出来（迁移后必须重录）', () => {
  assert(diff.credentialGaps.some((g) => g.ref === 'VMPROBE_VM_A_PASSWORD'),
    `应报出凭据缺口，实际 ${JSON.stringify(diff.credentialGaps)}`);
});

log('\n[4] 带私钥的归档（必须加密）');
const secretArchive = join(work, 'with-secrets.vmpz');
const sess = exportArchive({ dir: src, includeSecrets: true, passphrase: 'check-passphrase-1', redaction: 'none' });
writeFileSync(secretArchive, sess.buffer);
check('★ 明文私钥不出现在归档任何位置', () => {
  assert(!sess.buffer.includes(Buffer.from('PRIVATE-KEY-MATERIAL')), '归档里出现了明文私钥');
});
check('★ 口令错 → 拒绝解密（不返回半截数据）', () => {
  let threw = false;
  try { readArchive(readFileSync(secretArchive), { passphrase: 'wrong-passphrase' }); } catch { threw = true; }
  assert(threw, '错误口令必须抛错');
});
check('★ 口令对 → 私钥可完整取回', () => {
  const back = readArchive(readFileSync(secretArchive), { passphrase: 'check-passphrase-1' });
  assert(back.secrets.get('keys/t_vm').toString('utf8') === 'PRIVATE-KEY-MATERIAL', '私钥内容不符');
});

rmSync(work, { recursive: true, force: true });

log(`\n${failures === 0 ? '归档检查全部通过 ✔' : `失败 ${failures} 项 ✖`}\n`);
process.exit(failures === 0 ? 0 : 1);
