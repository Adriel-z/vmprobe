/**
 * 文档一致性检查 —— 确认 README / DEVELOPMENT 里提到的项目内路径**真的存在**。
 *
 * 为什么需要：文档里的路径最容易悄悄过期（本项目刚从 m0/ 重组到 tools/ 过一轮）。
 * 一条"文档承诺了不存在的文件"的假路径，和白纸黑字的错误一样会浪费别人的时间。
 *
 *   node tools/checks/check-docs.mjs
 */

import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DOCS = ['README.md', 'DEVELOPMENT.md', 'DESIGN.md', 'ISSUES.md', 'docs/M0-验证报告.md'];

/** 只检查这些前缀下的路径（避免把 URL、npm 包名、绝对系统路径当成项目内路径）。 */
const PREFIXES = ['tools/', 'packages/', 'agent/', 'docs/'];

/**
 * 允许"提及但尚不存在"的路径。
 * 这份清单**本身就是一份"还没做"的显式记录** —— 每加一项都应该对应路线图里的一个条目。
 */
const ALLOW_MISSING = new Set([
  'packages/plugin-client/',   // 路线图 M1-④：客户端 UI 插件（掩码凭据录入/状态徽标）
  'packages/transport/',       // 路线图 M1-①：SSH 传输层（ssh2 后端）
  'tools/facts-sample.json',   // 早期冒烟测试的产物，已清理，仅历史文档提及
]);

let problems = 0;
let checked = 0;

for (const doc of DOCS) {
  const p = join(ROOT, doc);
  if (!existsSync(p)) { console.log(`  ⚠ 文档不存在: ${doc}`); continue; }
  const text = readFileSync(p, 'utf8');

  // 抓取反引号或 markdown 链接里的候选路径
  const candidates = new Set();
  for (const m of text.matchAll(/`([^`\s]+)`/g)) candidates.add(m[1]);
  for (const m of text.matchAll(/\]\(([^)\s]+)\)/g)) candidates.add(m[1]);

  const missing = [];
  let planned = 0;
  for (const c of candidates) {
    const clean = c.replace(/[.,;:]$/, '');
    if (!PREFIXES.some((pre) => clean.startsWith(pre))) continue;
    if (clean.includes('*') || clean.includes('<') || clean.includes('…')) continue;  // 通配/占位
    checked++;
    if (ALLOW_MISSING.has(clean)) { planned++; continue; }
    if (!existsSync(join(ROOT, clean))) missing.push(clean);
  }
  if (missing.length) {
    problems += missing.length;
    console.log(`  ✖ ${doc} 提到但不存在：`);
    for (const m of [...new Set(missing)].sort()) console.log(`      ${m}`);
  } else {
    console.log(`  ✔ ${doc}${planned ? `（含 ${planned} 处"规划中"路径，已登记）` : ''}`);
  }
}

console.log(`\n检查了 ${checked} 处项目内路径引用`);
if (problems) {
  console.log(`发现 ${problems} 处失效引用 ✖  —— 请同步更新文档`);
  process.exit(1);
}
console.log('文档路径引用全部有效 ✔');
