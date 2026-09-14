/**
 * 凭据录入 CLI —— 让密码**永远不进对话、不进会话日志**。
 *
 * 为什么需要它（设计决策 D4）：DSH 会话是持久化并会被完整重放的。
 * 如果用户直接在聊天里说"密码是 xxx"，那串密码就永久留在会话存档里，
 * 还会被后续每一轮上下文注入。所以密码必须走**带掩码的交互式录入**，不能走对话。
 *
 * 本工具写入 DSH 自己的凭据库 `$DSH_HOME/.credentials.yaml`（条目是
 * `引用名 → 非空字符串` 的严格映射），因此主控端能用 `ctx.credentials.resolve(ref)`
 * 按需取用 —— 每次操作现取，改完无需重启 DSH（它 watch 这个文件）。
 *
 * ── 安全约定 ──────────────────────────────────────────────────────────────
 * · **绝不回显任何凭据值**：连长度都不打（长度也是信息）。只报"已设置/已删除/处于环境变量层"。
 * · 写入前**校验结果仍是合法 YAML**，并且**原子替换**（写临时文件再 rename）。
 * · 默认备份原文件；不覆盖来自环境变量的引用（那会造成"写了却没生效"的假象）。
 *
 *   node tools/vmprobe-cred.mjs list
 *   node tools/vmprobe-cred.mjs set VMPROBE_VM_A_PASSWORD
 *   node tools/vmprobe-cred.mjs check VMPROBE_VM_A_PASSWORD
 *   node tools/vmprobe-cred.mjs rm VMPROBE_VM_A_PASSWORD
 */

import { readFileSync, writeFileSync, renameSync, existsSync, copyFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

import { tryImportDshPackage } from './lib/dsh-runtime.mjs';

const HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh');
const FILE = join(HOME, '.credentials.yaml');

/** 引用名必须是 POSIX shell 标识符（与 DSH 凭据服务的约束一致）。 */
const REF_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * yaml 解析库：用**与 DSH 相同**的那一份（可移植解析，见 tools/lib/dsh-runtime.mjs）。
 * 只为了一个小工具再拉一个独立版本，就有"我这边能解析、DSH 那边起不来"的漂移风险。
 */
let YAML = null;
async function yaml() {
  if (YAML) return YAML;
  YAML = await tryImportDshPackage('yaml');
  if (!YAML) {
    console.error(
      '✖ 找不到 yaml 解析库（既没装在本项目里，也没能从 DSH 安装目录探测到）。\n'
      + '  可 `pnpm add -D yaml`，或用 DSH_RUNTIME_ROOT 指向含 node_modules/@deepseek-ai/dsh 的目录。',
    );
    process.exit(2);
  }
  return YAML;
}

/** 从终端读一行，**不回显**（TTY 下关闭 echo；管道下退化为普通读取）。 */
async function readHidden(prompt) {
  process.stdout.write(prompt);
  if (!process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin });
    const line = await new Promise((r) => rl.once('line', r));
    rl.close();
    return line;
  }
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (ch) => {
      switch (ch) {
        case '\r': case '\n': case '\u0004':
          stdin.removeListener('data', onData);
          if (typeof wasRaw === 'boolean') stdin.setRawMode(wasRaw);
          stdin.pause();
          process.stdout.write('\n');
          resolve(buf);
          break;
        case '\u0003': // Ctrl-C
          process.stdout.write('\n');
          process.exit(130);
          break;
        case '\u007f': case '\b':
          buf = buf.slice(0, -1);
          break;
        default:
          buf += ch; // 不回显
      }
    };
    stdin.on('data', onData);
  });
}

async function loadDoc() {
  const Y = await yaml();
  const text = existsSync(FILE) ? readFileSync(FILE, 'utf8') : '';
  const doc = Y.parseDocument(text || '{}\n', { prettyErrors: true, uniqueKeys: true });
  if (doc.errors.length) {
    console.error(`✖ 现有凭据文件不是合法 YAML（${doc.errors.length} 个错误）：`);
    for (const e of doc.errors) console.error(`   ${e.code} line ${e.linePos?.[0]?.line}`);
    console.error('   修法：node tools/fix-credentials.mjs --apply');
    process.exit(3);
  }
  return { Y, doc, text };
}

/** 原子写入，并在写前校验结果仍是合法 YAML。 */
async function saveDoc(doc, nextText) {
  const Y = await yaml();
  const check = Y.parseDocument(nextText, { prettyErrors: true, uniqueKeys: true });
  if (check.errors.length) {
    console.error('✖ 生成的文档不合法，**拒绝写入**（宁可不改也不破坏凭据库）：');
    for (const e of check.errors) console.error(`   ${e.code} line ${e.linePos?.[0]?.line}`);
    process.exit(4);
  }
  if (existsSync(FILE)) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    copyFileSync(FILE, `${FILE}.bak-${stamp}`);
  } else {
    const { mkdirSync } = await import('node:fs');
    mkdirSync(HOME, { recursive: true });
  }
  const tmp = `${FILE}.tmp-vmprobe-cred`;
  writeFileSync(tmp, nextText, 'utf8');
  renameSync(tmp, FILE);
}

/** 环境变量层是否已提供该引用（它会**遮住**文件层，写了也不生效）。 */
const envShadowed = (ref) => typeof process.env[ref] === 'string' && process.env[ref] !== '';

async function cmdSet(ref) {
  if (!REF_RE.test(ref)) {
    console.error(`✖ 引用名必须是 POSIX 标识符（字母/下划线开头），实际：${JSON.stringify(ref)}`);
    process.exit(2);
  }
  if (envShadowed(ref)) {
    console.error(`✖ 环境变量 ${ref} 已经存在，它会遮住文件层 —— 此时写文件不会生效。`);
    console.error('   请改用环境变量注入，或先清掉该环境变量再写入。');
    process.exit(5);
  }
  const first = await readHidden(`请输入 ${ref} 的值（不回显）：`);
  if (!first) {
    console.error('✖ 值为空。要删除请用 `rm` 子命令。');
    process.exit(6);
  }
  const again = await readHidden('请再次输入以确认：');
  if (first !== again) {
    console.error('✖ 两次输入不一致，未做任何修改。');
    process.exit(7);
  }

  const { doc } = await loadDoc();
  doc.set(ref, first);
  await saveDoc(doc, doc.toString());
  // 刻意不回显长度或任何片段 —— 长度也是信息
  console.log(`✔ 已写入 ${FILE}：${ref}`);
  console.log('  DSH 会 watch 这个文件，因此**无需重启**即可在下次操作时生效。');
}

async function cmdRm(ref) {
  const { doc } = await loadDoc();
  if (!doc.has(ref)) {
    console.log(`· ${ref} 本来就不在文件里（无操作）`);
    return;
  }
  doc.delete(ref);
  await saveDoc(doc, doc.toString());
  console.log(`✔ 已从 ${FILE} 删除：${ref}`);
}

async function cmdList() {
  const { doc } = await loadDoc();
  const keys = (doc.toJS() ?? {});
  const names = Object.keys(keys);
  if (!names.length) {
    console.log(`（${FILE} 里没有任何条目）`);
    return;
  }
  console.log(`凭据库 ${FILE} 的条目（只列名字，不显示任何值）：`);
  for (const n of names.sort()) {
    const shadow = envShadowed(n) ? '  ⚠ 同名环境变量存在（会遮住文件层）' : '';
    console.log(`  · ${n}${shadow}`);
  }
}

async function cmdCheck(ref) {
  const { doc } = await loadDoc();
  const inFile = doc.has(ref);
  const inEnv = envShadowed(ref);
  console.log(`引用 ${ref}：`);
  console.log(`  文件层 : ${inFile ? '已设置' : '未设置'}`);
  console.log(`  环境层 : ${inEnv ? '已设置（优先级更高，会遮住文件层）' : '未设置'}`);
  console.log(`  结论   : ${inFile || inEnv ? '可解析' : '**不可解析** —— 需要先用 set 录入'}`);
  if (!inFile && !inEnv) process.exit(1);
}

const [cmd, ref] = process.argv.slice(2);
switch (cmd) {
  case 'set': await cmdSet(ref ?? ''); break;
  case 'rm': await cmdRm(ref ?? ''); break;
  case 'list': await cmdList(); break;
  case 'check': await cmdCheck(ref ?? ''); break;
  default:
    console.log(`VMProbe 凭据录入 —— 密码不进对话的唯一入口

用法：
  node tools/vmprobe-cred.mjs list                列出条目名（不显示值）
  node tools/vmprobe-cred.mjs set <引用名>         交互式录入（不回显，需二次确认）
  node tools/vmprobe-cred.mjs check <引用名>       检查能否解析
  node tools/vmprobe-cred.mjs rm <引用名>          删除

凭据库位置：${FILE}
引用名示例：VMPROBE_VM_A_PASSWORD（POSIX 标识符形式）
`);
}
