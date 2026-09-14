/**
 * 修复 .credentials.yaml —— 目标：让它成为合法 YAML，**同时保证每一个原值一个字节都不变**。
 *
 * 已知病灶：文件中两行是"中文标签 + 全角冒号（U+FF1A）"的手写标注，不是合法 YAML。
 * 结果 DSH 无法启动（loader 里 credentials 条目 apply 失败 → 整棵插件树加载失败 → exit 1）。
 *
 * 本脚本的原则：
 *   1. **不打印任何凭据值**（连前几位都不打）；只输出键名、长度、sha256。
 *   2. **不猜键名就丢弃**：原标注降级为注释保留，值挂到按标签推断的键名下，
 *      并明确标注"键名为推断所得，不符请改"。
 *   3. **写前备份**，**原子替换**（避免 watch 中的活实例读到半个文件）。
 *   4. 修完用同一个 YAML 解析器**回读校验**：每个值的 sha256 必须与原文一致。
 *
 *   node tools/fix-credentials.mjs            # 预演（只报告，不写）
 *   node tools/fix-credentials.mjs --apply    # 实际写入
 */

import { readFileSync, writeFileSync, renameSync, copyFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { importDshPackage } from './lib/dsh-runtime.mjs';

// 用 DSH 自己那份 yaml 解析器（可移植解析，不再写死本机绝对路径 —— 技术债 #10）
const YAML = await importDshPackage('yaml');

const file = join(homedir(), '.dsh', '.credentials.yaml');
const apply = process.argv.includes('--apply');
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 16);

/** 本文件里哪些键是"真正的凭据条目"（其余形态一律按注释/标注处理）。 */
const ASCII_KEY = /^([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*:[ \t]?(.*)$/;

/**
 * 中文标注 → 真实键名。
 *
 * 这不是瞎猜，两条都有依据：
 *   · 知乎：`~/.dsh/skills/zhihu/references/cli.md` 明确读 `ZHIHU_ACCESS_SECRET`，
 *     且文档说明"不传 X-OAuth-Token 时查询 Access Secret 所属账号**本人**" ——
 *     与标注里的"个人"完全对应。
 *   · 方舟：方舟技能读 `ARK_API_KEY`（值形态也符合方舟 key 的 UUID 结构）。
 */
const LABEL_TO_KEY = [
  { test: (l) => l.includes('知乎'), key: 'ZHIHU_ACCESS_SECRET', why: 'zhihu 技能文档明确读取该环境变量（见 references/cli.md）' },
  { test: (l) => l.includes('方舟') || l.includes('火山'), key: 'ARK_API_KEY', why: '方舟技能读取该环境变量，且值形态为方舟 key 的 UUID 结构' },
];

/** YAML 双引号标量的转义。 */
function yamlDQ(s) {
  let out = '"';
  for (const ch of s) {
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (ch.codePointAt(0) < 0x20) out += `\\x${ch.codePointAt(0).toString(16).padStart(2, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

/** 去掉一层引号（若有）。 */
function unquote(v) {
  const t = v.trim();
  if (t.length >= 2 && ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'")))) {
    return t.slice(1, -1);
  }
  return t;
}

const raw = readFileSync(file, 'utf8');
const eol = raw.includes('\r\n') ? '\r\n' : '\n';
const lines = raw.split(/\r?\n/);

/** 原始条目：键名 → 值（用于修后比对）。 */
const original = new Map();
/** 非 ASCII 键的行（即那两行标注）。 */
const annotations = [];

const outLines = [];
outLines.push('# 由 VMProbe 修复：原文件含两行"中文标签 + 全角冒号"的手写标注，不是合法 YAML，');
outLines.push('# 会导致 DSH 启动时 credentials 条目 apply 失败（整棵插件树加载失败、进程 exit 1）。');
outLines.push('# 已保留全部原值（sha256 可核对）；原中文标注降级为注释；值统一改为双引号标量。');
outLines.push('');

lines.forEach((line, i) => {
  const n = i + 1;
  const trimmed = line.trim();

  if (trimmed === '') { outLines.push(''); return; }
  if (trimmed.startsWith('#')) { outLines.push(line); return; }

  const m = ASCII_KEY.exec(line);
  if (m) {
    const key = m[1];
    const value = unquote(m[2]);
    original.set(key, value);
    outLines.push(`${key}: ${yamlDQ(value)}`);
    return;
  }

  // 非 ASCII 键的行：拆出"标签 + 值"。分隔符可能是全角冒号或半角冒号。
  const sepMatch = /^(.*?)[：:](.*)$/.exec(trimmed);
  if (sepMatch) {
    const label = sepMatch[1].trim();
    const value = sepMatch[2].trim();
    const mapped = LABEL_TO_KEY.find((m) => m.test(label));
    const key = mapped ? mapped.key : `VMPROBE_INFERRED_${annotations.length + 1}`;
    annotations.push({ line: n, label, value, key, why: mapped?.why ?? null });
    outLines.push(`# ── 原第 ${n} 行标注（原标签与值均未改动）──`);
    outLines.push(`# 原标注：${label}`);
    outLines.push(mapped
      ? `# 键名依据：${mapped.why}`
      : '# ⚠️ 键名是占位：无法从标注推断它对应哪个环境变量，请改名或删除。');
    outLines.push(`${key}: ${yamlDQ(value)}`);
    outLines.push('');
    return;
  }

  // 既不是键行、也不是可切分的标注 —— 不猜，原样注释掉并告警
  outLines.push(`# ⚠️ 无法解析的第 ${n} 行，已注释保留（原文未改动）：`);
  outLines.push(`# ${line}`);
  outLines.push('');
});

const next = `${outLines.join(eol)}`;

// ── 校验 1：新文本必须是合法 YAML，且字段数与原文条目数一致 ──
const doc = YAML.parseDocument(next, { prettyErrors: true, uniqueKeys: true });
if (doc.errors.length) {
  console.error('✖ 生成的文本仍不是合法 YAML：');
  for (const e of doc.errors) console.error(`   ${e.code} line ${e.linePos?.[0]?.line}`);
  process.exit(1);
}
const parsed = doc.toJS() ?? {};

// ── 校验 2：每个原值的 sha256 必须一字不差 ──
let mismatched = 0;
console.log('值保真校验（只比 sha256，不显示值）');
console.log('='.repeat(72));
for (const [key, value] of original) {
  const after = parsed[key];
  const same = typeof after === 'string' && sha(after) === sha(value);
  if (!same) mismatched++;
  console.log(`${same ? '✔' : '✖'} ${key.padEnd(46)} 原 ${sha(value)} → 新 ${same ? sha(after) : '(不一致)'} len=${value.length}`);
}
for (const [i, a] of annotations.entries()) {
  const after = parsed[a.key];
  const same = typeof after === 'string' && sha(after) === sha(a.value);
  if (!same) mismatched++;
  console.log(`${same ? '✔' : '✖'} ${a.key.padEnd(46)} 原 ${sha(a.value)} → 新 ${same ? sha(after) : '(不一致)'} len=${a.value.length}  【原标注：${a.label}】`);
}
console.log('');
console.log(`恢复出的字段总数 = ${Object.keys(parsed).length}（原条目 ${original.size} + 标注 ${annotations.length} = ${original.size + annotations.length}）`);

if (mismatched) {
  console.error(`\n✖ 有 ${mismatched} 个值不一致，**拒绝写入**（宁可不修，也不能改坏凭据）`);
  process.exit(1);
}
console.log('✔ 全部值 sha256 一致');

if (!apply) {
  console.log('\n（预演模式，未写入。加 --apply 实际写入）');
  process.exit(0);
}

// ── 备份 + 原子替换 ──
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const backup = `${file}.bak-${stamp}`;
copyFileSync(file, backup);
console.log(`\n已备份原文件 → ${backup}（存在=${existsSync(backup)}）`);

const tmp = `${file}.tmp-vmprobe`;
writeFileSync(tmp, next, 'utf8');
renameSync(tmp, file);
console.log(`已原子替换 → ${file}`);
console.log(`新文件大小 = ${readFileSync(file, 'utf8').length} 字节`);
