/**
 * 协从端脚本检查的**跨平台启动器**。
 *
 * 为什么需要它：两个检查脚本是 POSIX sh（因为它们测的就是那个 sh 脚本），
 * 但 Windows 上 `bash` 通常**不在 PATH 里**（Git for Windows 装了 bash，只是在别处）。
 * 结果就是 `npm run check` 在这台开发机上直接失败 —— 一个"一条命令自检"的入口不该这样。
 *
 * 本文件负责：找到 bash（PATH → 常见 Git 安装位置）→ 依次跑三项检查 → 汇总退出码。
 * 找不到 bash 时**明确跳过并说明**（默认退出 0；加 --strict 则视为失败）。
 *
 *   node tools/checks/run-agent-checks.mjs [--strict]
 */

import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const strict = process.argv.includes('--strict');

/** 找 bash：先 PATH，再几个常见位置。 */
function findBash() {
  const probe = process.platform === 'win32'
    ? spawnSync('where', ['bash'], { encoding: 'utf8' })
    : spawnSync('sh', ['-c', 'command -v bash'], { encoding: 'utf8' });
  if (probe.status === 0 && probe.stdout.trim()) {
    return probe.stdout.split(/\r?\n/)[0].trim();
  }
  const candidates = [
    'C:\\Program Files\\Git\\bin\\bash.exe',
    'C:\\Program Files (x86)\\Git\\bin\\bash.exe',
    '/bin/bash',
    '/usr/bin/bash',
    '/usr/local/bin/bash',
  ];
  return candidates.find((p) => existsSync(p)) ?? null;
}

const bash = findBash();
if (!bash) {
  const msg = '未找到 bash —— 跳过协从端脚本检查（安装 Git for Windows 或把 bash 放进 PATH 后重跑）';
  console.log(`\n⚠ ${msg}`);
  process.exit(strict ? 1 : 0);
}

console.log(`bash = ${bash}\n`);

const CHECKS = [
  { name: '语法检查 agent/bootstrap.sh', args: ['-n', join(ROOT, 'agent', 'bootstrap.sh')] },
  { name: '不可信输入转义', args: [join(HERE, 'check-escape.sh')] },
  { name: '安装完整性守卫', args: [join(HERE, 'check-install-guard.sh')] },
];

let failed = 0;
for (const c of CHECKS) {
  process.stdout.write(`── ${c.name} … `);
  const r = spawnSync(bash, c.args, { encoding: 'utf8', cwd: ROOT });
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`.trim();
  if (r.status === 0) {
    console.log('✔');
    if (out && !c.args.includes('-n')) {
      // 打印子脚本的关键结论行（避免刷屏：只保留含 ✔/✖/通过/失败 的行）
      for (const line of out.split(/\r?\n/)) {
        if (/[✔✖]|通过|失败/.test(line)) console.log(`     ${line.trim()}`);
      }
    }
  } else {
    failed += 1;
    console.log(`✖ (exit ${r.status})`);
    console.log(out.split(/\r?\n/).map((l) => `     ${l}`).join('\n'));
  }
}

console.log('');
if (failed) {
  console.log(`协从端检查失败 ${failed} 项 ✖`);
  process.exit(1);
}
console.log('协从端检查全部通过 ✔');
