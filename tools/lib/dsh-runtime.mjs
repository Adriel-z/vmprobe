/**
 * DSH 运行时依赖的可移植解析（技术债 #10）。
 *
 * ── 问题 ──────────────────────────────────────────────────────────────────
 * 项目里几个开发工具需要 DSH 自带的两个包：
 *   · `@deepseek-ai/dsh-tools` —— 用**宿主自己的** JSON Schema 校验器验我们的工具定义；
 *   · `yaml`                    —— 用 DSH 用的**同一个**解析器读 `.credentials.yaml`
 *                                  （校验器不同会导致"我这边能解析、DSH 那边起不来"）。
 *
 * 但这两个包都**不是**本项目的依赖：前者没发布到 npm（`npm view` 超时/不存在），
 * 后者虽然能装，但装成独立版本就可能与 DSH 实际使用的版本漂移。
 * 于是最初的实现把**本机绝对路径**写死在源码里：
 *
 *     'C:/Users/-/.workbuddy/binaries/node/versions/22.22.2-2/node_modules/@deepseek-ai/dsh/...'
 *
 * 后果很直接：**换一台机器、换一个 Node 版本、换一次 DSH 升级，全部开发工具就都跑不起来**，
 * 而报错还是"模块找不到"这种指不到原因的形式。这正是技术债 #10 要消掉的东西。
 *
 * ── 做法：按"可能的运行时根"逐个探测，而不是写死路径 ──────────────────────
 * 优先级从"最明确"到"最兜底"：
 *   ① 环境变量 `DSH_RUNTIME_ROOT`（显式逃生口：非标准布局时用户自己指）
 *   ② 沿 `dsh` 可执行文件（`dsh` / `dsh.cmd` / `dsh.ps1`）所在目录向上找 `node_modules`
 *   ③ 当前 Node 前缀下的 `node_modules`（`process.execPath` 推导，覆盖全局安装）
 *   ④ `<prefix>/lib/node_modules`（类 Unix 全局安装布局）
 * 每个根下再查两个位置：根自身的 `node_modules/<pkg>`，以及
 * `<root>/node_modules/@deepseek-ai/dsh/node_modules/<pkg>`（**嵌套依赖**，
 * `yaml` 就在那儿 —— 这也解释了为什么只查顶层会找不到）。
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);

/** 把 `dsh` 可执行文件的位置找出来（仅用于推导运行时根）。 */
function findDshExecutable() {
  const names = process.platform === 'win32' ? ['dsh.cmd', 'dsh.ps1', 'dsh.exe', 'dsh'] : ['dsh'];
  const probe = process.platform === 'win32' ? 'where' : 'which';
  for (const name of names) {
    try {
      const out = execFileSync(probe, [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
        .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (out.length) return out[0];
    } catch { /* 没装或不在 PATH：继续试下一个名字 */ }
  }
  // PATH 里没有也能猜：本项目已知的安装形态是 <node-prefix>/<...>/node_modules/@deepseek-ai/dsh
  const prefix = dirname(process.execPath);
  const guess = join(prefix, 'node_modules', '@deepseek-ai', 'dsh', 'package.json');
  return existsSync(guess) ? join(prefix, 'dsh') : null;
}

/** 从某个起点向上找最近的、含有 `@deepseek-ai/dsh` 的 node_modules 根。 */
function runtimeRootsFrom(start) {
  const roots = [];
  let dir = start;
  for (let i = 0; i < 8 && dir; i += 1) {
    const nm = join(dir, 'node_modules');
    if (existsSync(join(nm, '@deepseek-ai', 'dsh', 'package.json'))) roots.push(dir);
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return roots;
}

/** 收集全部候选运行时根。 */
export function dshRuntimeRoots() {
  const roots = [];
  const push = (r) => { if (r && !roots.includes(r)) roots.push(r); };

  push(process.env.DSH_RUNTIME_ROOT);

  const exe = findDshExecutable();
  if (exe) for (const r of runtimeRootsFrom(dirname(exe))) push(r);

  const nodePrefix = dirname(process.execPath);
  for (const r of runtimeRootsFrom(nodePrefix)) push(r);
  push(nodePrefix);
  push(join(nodePrefix, 'lib'));

  return roots;
}

/**
 * 解析一个 DSH 运行时包的**入口文件绝对路径**。
 * @param {string} name 包名，如 `yaml` 或 `@deepseek-ai/dsh-tools`
 * @returns {string|null}
 */
export function resolveDshPackage(name) {
  // ① 最省事的情况：本项目自己装了（或 Node 能直接解析到）就用它
  try {
    const direct = require.resolve(name);
    if (typeof direct === 'string' && existsSync(direct)) return direct;
  } catch { /* 没装：走下面的探测 */ }

  for (const root of dshRuntimeRoots()) {
    const candidates = [
      join(root, 'node_modules', name),
      // DSH 自己的嵌套依赖（yaml 在这里）
      join(root, 'node_modules', '@deepseek-ai', 'dsh', 'node_modules', name),
    ];
    for (const pkgDir of candidates) {
      const pkgJson = join(pkgDir, 'package.json');
      if (!existsSync(pkgJson)) continue;
      try {
        const meta = JSON.parse(readFileSync(pkgJson, 'utf8'));
        const entry = entryOf(meta);
        const file = join(pkgDir, entry);
        if (existsSync(file)) return file;
        // 入口推导失败时兜一个常见的默认位置
        for (const fallback of ['index.js', 'dist/index.js', 'lib/index.js']) {
          const f = join(pkgDir, fallback);
          if (existsSync(f)) return f;
        }
      } catch { /* package.json 坏了：试下一个候选 */ }
    }
  }
  return null;
}

/** 从 package.json 里推导一个可用于**文件导入**的入口。 */
function entryOf(meta) {
  const exp = meta.exports;
  if (typeof exp === 'string') return exp.replace(/^\.\//, '');
  if (exp && typeof exp === 'object') {
    const dot = exp['.'] ?? exp;
    if (typeof dot === 'string') return dot.replace(/^\.\//, '');
    if (dot && typeof dot === 'object') {
      const pick = dot.import ?? dot.node ?? dot.default;
      if (typeof pick === 'string') return pick.replace(/^\.\//, '');
      if (pick && typeof pick === 'object' && typeof pick.default === 'string') {
        return pick.default.replace(/^\.\//, '');
      }
      // 条件导出里再兜一层常见形态
      for (const v of Object.values(dot)) {
        if (typeof v === 'string' && v.endsWith('.js')) return v.replace(/^\.\//, '');
      }
    }
    // 子路径导出（有些包只声明 './xxx'）
    for (const [key, v] of Object.entries(exp)) {
      if (key === '.' || !key.startsWith('./') || key.includes('*')) continue;
      const val = typeof v === 'string' ? v : (v?.import ?? v?.default);
      if (typeof val === 'string' && val.endsWith('.js')) return val.replace(/^\.\//, '');
    }
  }
  return (meta.main ?? 'index.js').replace(/^\.\//, '');
}

/**
 * 动态 import 一个 DSH 运行时包。
 * @throws {Error} 找不到时给出**可操作**的报错（而不是裸的 ERR_MODULE_NOT_FOUND）
 */
export async function importDshPackage(name) {
  const file = resolveDshPackage(name);
  if (!file) {
    throw new Error(
      `找不到 DSH 运行时包 ${name}。已探测的运行时根：\n`
      + dshRuntimeRoots().map((r) => `  · ${r}`).join('\n')
      + `\n可设环境变量 DSH_RUNTIME_ROOT 指向含有 node_modules/@deepseek-ai/dsh 的目录后重试。`,
    );
  }
  return import(pathToFileURL(file).href);
}

/** 同 `importDshPackage`，但失败返回 `null`（用于"有则更好"的场景）。 */
export async function tryImportDshPackage(name) {
  try {
    return await importDshPackage(name);
  } catch {
    return null;
  }
}

/** 供 doctor / 自检使用：把探测结论列出来。 */
export function describeRuntime() {
  return {
    roots: dshRuntimeRoots(),
    dshExecutable: findDshExecutable(),
    nodePrefix: dirname(process.execPath),
    resolved: {
      yaml: resolveDshPackage('yaml'),
      '@deepseek-ai/dsh-tools': resolveDshPackage('@deepseek-ai/dsh-tools'),
    },
  };
}

export { readdirSync };
