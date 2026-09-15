/**
 * VMProbe 归档工具 —— 导出 / 查看 / 导入（`.vmpz`，DESIGN.md §11）。
 *
 *   node tools/vmprobe-archive.mjs export <文件.vmpz> [选项]
 *   node tools/vmprobe-archive.mjs inspect <文件.vmpz>
 *   node tools/vmprobe-archive.mjs import <文件.vmpz> [选项]
 *
 * 选项（export）：
 *   --include-audit        带上审计链（logs/）
 *   --include-runs         带上运行记录（runs/）
 *   --include-secrets      带上私钥（**必须**同时给口令，否则拒绝）
 *   --redact <档位>        none | minimal | standard（默认 standard）
 *
 * 选项（import）：
 *   --apply                真正写入；**不加就是预演**（只看差异）
 *   --overwrite            允许覆盖本地已有的不同文件（会先备份为 *.vmpz-bak）
 *   --dir <路径>           目标 storageDir（默认 $DSH_HOME/vmprobe）
 *
 * ── 口令怎么给（刻意只支持两种，且都有原因）────────────────────────────────
 *   · 交互式：TTY 下提示输入，**不回显**（默认）
 *   · `--passphrase-env VAR`：从环境变量读，供脚本/CI 用
 * **不接受**把口令写成命令行参数 —— 它会进 shell 历史与进程列表（`ps` 里人人可见）。
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';

import {
  applyImport, diffArchive, exportArchive, readArchive,
} from '../packages/core/src/index.js';

const argv = process.argv.slice(2);
const cmd = argv[0];
const file = argv[1];

const flag = (name) => argv.includes(`--${name}`);
const opt = (name, fallback = null) => {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
};

const DEFAULT_DIR = process.env.DSH_HOME ? join(process.env.DSH_HOME, 'vmprobe') : join(homedir(), '.dsh', 'vmprobe');

/** 问用户要口令（不回显）。 */
async function askPassphrase(prompt) {
  const envVar = opt('passphrase-env');
  if (envVar) {
    const v = process.env[envVar];
    if (!v) throw new Error(`环境变量 ${envVar} 为空`);
    return v;
  }
  if (!process.stdin.isTTY) {
    throw new Error(
      '需要口令，但当前不是交互式终端。请用 --passphrase-env VAR（从环境变量读）。\n'
      + '  不要把口令写在命令行参数里 —— 它会进 shell 历史与进程列表。',
    );
  }
  process.stdout.write(prompt);
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  return new Promise((resolvePromise, reject) => {
    // 关闭回显：readline 的 terminal 模式把输出接管后，用 _writeToOutput 拦掉
    const original = rl._writeToOutput?.bind(rl);
    rl._writeToOutput = (s) => { if (s.includes('\n')) original?.(s); };
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      if (!answer) reject(new Error('口令不能为空'));
      else resolvePromise(answer);
    });
  });
}

function stageDir() {
  return resolve(opt('dir', DEFAULT_DIR));
}

function usage() {
  console.log(readFileSync(new URL(import.meta.url), 'utf8').split('*/')[0].replace(/^\/\*\*?/, '').trim());
  process.exit(cmd ? 1 : 0);
}

if (!cmd || !['export', 'import', 'inspect'].includes(cmd)) usage();
if (!file) usage();

const target = resolve(file);

// ── export ──────────────────────────────────────────────────────────────────
if (cmd === 'export') {
  const dir = stageDir();
  const includeSecrets = flag('include-secrets');
  const redaction = opt('redact', 'standard');
  const dirExists = existsSync(dir);

  let passphrase = null;
  if (includeSecrets) {
    if (!dirExists) { console.error(`✖ storageDir 不存在：${dir}`); process.exit(2); }
    passphrase = await askPassphrase('为私钥设置归档口令（不回显，至少 8 位）：');
    const again = await askPassphrase('再输一次确认：');
    if (passphrase !== again) { console.error('✖ 两次输入不一致'); process.exit(2); }
    if (passphrase.length < 8) { console.error('✖ 口令至少 8 个字符'); process.exit(2); }
  }

  if (!dirExists) {
    console.error(`✖ storageDir 不存在：${dir}\n  （还没跑过 VMProbe？先添加一个目标，或显式 --dir 指到别处）`);
    process.exit(2);
  }

  const { buffer, manifest } = exportArchive({
    dir,
    version: '0.3.0',
    includeAudit: flag('include-audit'),
    includeRuns: flag('include-runs'),
    includeSecrets,
    redaction,
    passphrase,
  });
  writeFileSync(target, buffer);

  console.log(`✔ 已导出 ${target}`);
  console.log(`  条目 ${manifest.counts.files} 个（私钥 ${manifest.counts.secretFiles} 个，`
    + `${manifest.includes.secrets ? `已加密：${manifest.includes.secretsEncrypted}` : '不含私钥'}）`);
  console.log(`  脱敏档位：${manifest.redaction}｜审计链：${manifest.includes.audit ? '含' : '不含'}｜`
    + `运行记录：${manifest.includes.runs ? '含' : '不含'}`);
  if (manifest.counts.skipped) {
    console.log(`  跳过 ${manifest.counts.skipped} 个（含审计密钥/私钥等），清单里逐条记了原因：`);
    for (const s of manifest.skipped.slice(0, 5)) console.log(`    · ${s.path} —— ${s.reason}`);
  }
  process.exit(0);
}

// ── inspect ─────────────────────────────────────────────────────────────────
if (cmd === 'inspect') {
  if (!existsSync(target)) { console.error(`✖ 文件不存在：${target}`); process.exit(2); }
  const buf = readFileSync(target);
  const { manifest, files } = (() => {
    try {
      return readArchive(buf);
    } catch (err) {
      // 若是"缺口令"这类可恢复情况，提示怎么继续；其它情况直接把原因说清
      if (/口令/.test(err.message)) {
        console.error(`✖ ${err.message}\n  查看时也需要口令，请用 --passphrase-env VAR 重试。`);
        process.exit(3);
      }
      throw err;
    }
  })();
  console.log(`归档：${target}（${(buf.length / 1024).toFixed(1)} KiB）`);
  console.log(`  schema    : ${manifest.schema}`);
  console.log(`  生成于    : ${manifest.createdAt}（${manifest.producer?.platform ?? '?'}，v${manifest.producer?.version ?? '?'}）`);
  console.log(`  脱敏档位  : ${manifest.redaction}`);
  console.log(`  含审计链  : ${manifest.includes.audit ? '是' : '否'}｜含运行记录：${manifest.includes.runs ? '是' : '否'}`);
  console.log(`  含私钥    : ${manifest.includes.secrets ? `是（${manifest.includes.secretsEncrypted}）` : '否'}`);
  console.log(`  文件 ${files.size} 个：`);
  for (const [rel, data] of [...files].slice(0, 30)) console.log(`    ${rel}（${data.length} 字节）`);
  if (files.size > 30) console.log(`    … 其余 ${files.size - 30} 个`);
  if (manifest.skipped?.length) {
    console.log(`  导出时跳过 ${manifest.skipped.length} 个：`);
    for (const s of manifest.skipped.slice(0, 8)) console.log(`    ${s.path} —— ${s.reason}`);
  }
  process.exit(0);
}

// ── import ──────────────────────────────────────────────────────────────────
if (cmd === 'import') {
  if (!existsSync(target)) { console.error(`✖ 文件不存在：${target}`); process.exit(2); }
  const dir = stageDir();
  const apply = flag('apply');
  const overwrite = flag('overwrite');

  const needsPassphrase = (() => {
    try {
      readArchive(readFileSync(target));
      return false;
    } catch (err) {
      if (/必须提供口令/.test(err.message)) return true;
      throw err;                                  // 其它错误（schema/篡改）直接抛
    }
  })();

  let passphrase = null;
  if (needsPassphrase) passphrase = await askPassphrase('该归档含加密私钥，请输入口令（不回显）：');

  const archive = readArchive(readFileSync(target), { passphrase });
  const diff = diffArchive({ archive, dir });

  console.log(`归档：${target}`);
  console.log(`目标 storageDir：${dir}${existsSync(dir) ? '' : '（不存在，导入时会创建）'}`);
  console.log(`\n差异预览：`);
  console.log(`  新增   ${diff.added.length} 个`);
  for (const f of diff.added.slice(0, 10)) console.log(`    + ${f.path}`);
  if (diff.added.length > 10) console.log(`    … 其余 ${diff.added.length - 10} 个`);
  console.log(`  一致   ${diff.identical.length} 个（不会动）`);
  console.log(`  冲突   ${diff.conflict.length} 个${diff.conflict.length && !overwrite ? '（默认不覆盖）' : ''}`);
  for (const f of diff.conflict.slice(0, 10)) console.log(`    ! ${f.path}（本地 ${f.localBytes} 字节 ≠ 归档 ${f.bytes} 字节）`);
  if (diff.secrets.length) console.log(`  私钥   ${diff.secrets.length} 个（解密后写入，权限 0600）`);
  if (diff.credentialGaps.length) {
    console.log(`\n⚠ 凭据缺口 ${diff.credentialGaps.length} 个 —— 导入后必须重新录入，否则这些目标连不上：`);
    for (const g of diff.credentialGaps) {
      console.log(`    ${g.targetId} → ${g.ref}`);
    }
    console.log(`  录入方式：node tools/vmprobe-cred.mjs set <引用名>（交互式、不回显）`);
  }

  if (!apply) {
    console.log(`\n（预演：未写入任何文件。确认无误后加 --apply 执行${diff.conflict.length ? '，冲突文件还需 --overwrite' : ''}）`);
    process.exit(0);
  }

  const res = applyImport({ archive, dir, overwrite });
  console.log(`\n✔ 已导入：写入 ${res.written.length} 个，跳过 ${res.skipped.length} 个，`
    + `备份 ${res.backedUp.length} 个${res.secretsWritten.length ? `，私钥 ${res.secretsWritten.length} 个` : ''}`);
  for (const f of res.written.slice(0, 10)) console.log(`    ✔ ${f}`);
  if (res.skipped.length) {
    console.log(`  未写入（本地已存在且不同，或内容一致）：`);
    for (const f of res.skipped.slice(0, 10)) console.log(`    · ${f}`);
  }
  if (diff.credentialGaps.length) {
    console.log(`\n⚠ 别忘了补凭据：${diff.credentialGaps.map((g) => g.ref).join('、')}`);
  }
  process.exit(0);
}
