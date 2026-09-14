/**
 * VMProbe 环境预检（doctor）—— 在不启动 DSH 的前提下，提前发现"会让 DSH 起不来"的问题。
 *
 * 为什么需要它：
 *   实测发现一个 failing 的 loader entry 会让**整棵插件树加载失败**、进程直接 exit 1。
 *   也就是说 `~/.dsh/.credentials.yaml` 里一行写错，就能让整个 GUI 打不开。
 *   这类问题在"已经关掉 DSH、准备重启"的时刻才暴露，代价极高 —— 所以要有离线预检。
 *
 * 只读，不修改任何文件。**不打印任何凭据值**（只输出键名、长度、sha256）。
 *
 *   node tools/doctor.mjs
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { importDshPackage, describeRuntime } from './lib/dsh-runtime.mjs';

const HOME = join(homedir(), '.dsh');
const HERE = dirname(fileURLToPath(import.meta.url));
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 12);

let problems = 0;
let warnings = 0;
const ok = (m) => console.log(`  ✔ ${m}`);
const bad = (m) => { problems++; console.log(`  ✖ ${m}`); };
const warn = (m) => { warnings++; console.log(`  ⚠ ${m}`); };

console.log('\n[1] 凭据文件（失败会让整棵插件树加载不出来）');
const credFile = join(HOME, '.credentials.yaml');
if (!existsSync(credFile)) {
  warn(`${credFile} 不存在（DSH 可启动，但没有可用凭据）`);
} else {
  const text = readFileSync(credFile, 'utf8');
  const YAML = await importDshPackage('yaml');
  const doc = YAML.parseDocument(text, { prettyErrors: true, uniqueKeys: true });
  if (doc.errors.length) {
    bad(`YAML 解析失败（${doc.errors.length} 个错误）—— DSH 将无法启动：`);
    for (const e of doc.errors) {
      console.log(`      ${e.code} line ${e.linePos?.[0]?.line} col ${e.linePos?.[0]?.col}`);
    }
    console.log('      修法：node tools/fix-credentials.mjs          （预演）');
    console.log('            node tools/fix-credentials.mjs --apply  （实际写入，带备份与保真校验）');
  } else {
    const obj = doc.toJS() ?? {};
    ok(`YAML 合法，${Object.keys(obj).length} 个字段`);
    for (const [k, v] of Object.entries(obj)) {
      const kind = typeof v === 'string' ? `len=${v.length} sha=${sha(v)}` : `非字符串(${typeof v})`;
      console.log(`      · ${k}  ${kind}`);
      if (typeof v !== 'string') warn(`      ↑ 值不是字符串，凭据提供方可能不接受`);
    }
  }
  const st = statSync(credFile);
  console.log(`      文件 mtime = ${st.mtime.toISOString()}（注意：晚于 DSH 启动时间才可能是"当下已坏但暂时没暴露"）`);
}

console.log('\n[2] 叠加层引用的入口文件');
for (const name of ['overlay.yml', 'overlay-bogus.yml']) {
  const p = join(HERE, name);
  if (!existsSync(p)) { warn(`${name} 不存在（跳过）`); continue; }
  // overlay-bogus.yml 是"差分实验"的**故意无效**用例（用来证明 Loader 确实会解析并 import，
  // 而不是 --help 提前短路），因此它的"问题"是预期的，不该算预检失败。
  if (name.includes('bogus')) {
    console.log(`      ${name} —— 故意无效的差分实验用例，跳过检查（见文件头注释）`);
    continue;
  }
  const text = readFileSync(p, 'utf8');
  const m = /name:\s*'([^']+)'/.exec(text);
  if (!m) { warn(`${name} 里没有 name 字段`); continue; }
  const spec = m[1];
  if (spec.startsWith('file://')) {
    const fsPath = fileURLToPath(spec);
    if (!existsSync(fsPath)) { bad(`${name} 指向的文件不存在：${fsPath}`); continue; }
    if (statSync(fsPath).isDirectory()) {
      bad(`${name} 指向的是**目录** —— Node ESM 不支持目录导入（ERR_UNSUPPORTED_DIR_IMPORT），必须指向入口文件`);
      continue;
    }
    ok(`${name} → ${fsPath}（存在，且是文件）`);
  } else if (/^[A-Za-z]:\\/.test(spec)) {
    bad(`${name} 用的是裸 Windows 绝对路径 —— ESM loader 只接受 file:// URL（Received protocol 'c:'）`);
  } else {
    console.log(`      ${name} → 包名 "${spec}"（需能从 profile 的 node_modules 解析）`);
  }
}

console.log('\n[3] profile 与组合');
const profileDir = join(HOME, 'profiles', 'web');
for (const f of ['package.json', 'cordis.yml', 'cordis.patch.yml']) {
  if (existsSync(join(profileDir, f))) ok(`${f} 存在`);
  else bad(`${f} 缺失`);
}
const pkgPath = join(profileDir, 'package.json');
/** 本机 profile 是否已装 vmprobe（后面对比 overlay 的 id 冲突要用）。 */
let profileHasVmprobe = false;
if (existsSync(pkgPath)) {
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    const deps = Object.keys(pkg.dependencies ?? {});
    console.log(`      依赖 ${deps.length} 个：${deps.join(', ') || '(无)'}`);
    const bundles = pkg.dsh?.profile?.bundles ?? [];
    console.log(`      bundles：${bundles.join(', ') || '(无)'}`);
    profileHasVmprobe = deps.some((d) => d.includes('vmprobe'));
    if (!profileHasVmprobe) {
      warn('profile 里没有 vmprobe 相关依赖 —— 插件目前只能经 --patch 叠加层加载（重启后不会自动出现）');
    } else {
      ok('profile 里已声明 vmprobe 依赖（重启后自动生效）');
    }
  } catch (err) {
    bad(`package.json 解析失败：${err.message}`);
  }
}

// ---- [3.5] overlay 与已安装 bundle 的 **entry id 冲突** ----
//
// 实测抓到过：插件作为 bundle 装入 profile 后，它自带的 cordis.patch.yml 会插入
// `id: vmprobe-host`；此时再用 tools/overlay.yml（同 id）启动，DSH 直接失败：
//     plugin tree failed to load: duplicate loader entry id: vmprobe-host
// 这是"整棵树加载失败 → exit 1"的致命形态，所以必须在离线阶段就提醒。
console.log('\n[3.5] overlay 与已安装 bundle 的 id 冲突');const overlayPath = join(HERE, 'overlay.yml');
const pluginPatchPath = join(HERE, '..', 'packages', 'plugin-host', 'cordis.patch.yml');
const idsOf = (file) => {
  if (!existsSync(file)) return [];
  return [...readFileSync(file, 'utf8').matchAll(/^\s*-?\s*id:\s*([A-Za-z0-9._-]+)/gm)].map((m) => m[1]);
};
const overlayIds = idsOf(overlayPath);
const bundleIds = idsOf(pluginPatchPath);
const clash = overlayIds.filter((x) => bundleIds.includes(x));
if (profileHasVmprobe && clash.length) {
  warn(`profile 已装 vmprobe，且 overlay 与 bundle 的 entry id 冲突：${clash.join(', ')}`);
  console.log('      → **不要**再用 --patch tools/overlay.yml 启动（会导致 duplicate loader entry id，整棵树加载失败）');
  console.log('      → 已安装时开发循环：直接改源码（依赖是 link:，即时生效）→ 起临时实例验证');
  console.log('      → 只有"干净环境里验证挂载"才用 overlay');
} else if (clash.length) {
  console.log(`      overlay id = ${overlayIds.join(', ')}；bundle id = ${bundleIds.join(', ')}`);
  warn(`存在同 id（${clash.join(', ')}）但 profile 未安装 vmprobe —— 目前安全，安装后请勿再用 overlay`);
} else {
  ok('无 id 冲突');
}

console.log('\n[3.6] bundles 与 dependencies 的一致性');
//
// 实测发现：`dsh plugin add <带 dsh.bundle 的包>` 会**同时**改两处 ——
//   dependencies 里加依赖，**并且**把包名加进 `dsh.profile.bundles`。
// 反之，卸载时若只删依赖、留着 bundles 里的名字，启动时会因"解析不到 bundle"而失败。
// 这又是一条"整棵树加载不出来"的致命误配置，所以离线就检查。
{
  const pkgPath2 = join(profileDir, 'package.json');
  if (existsSync(pkgPath2)) {
    const pkg2 = JSON.parse(readFileSync(pkgPath2, 'utf8'));
    const deps2 = Object.keys(pkg2.dependencies ?? {});
    const bl = pkg2.dsh?.profile?.bundles ?? [];
    const orphan = bl.filter((b) => b.startsWith('@vmprobe') && !deps2.includes(b));
    const notBundled = deps2.filter((d) => d.startsWith('@vmprobe') && !bl.includes(d));
    if (orphan.length) {
      bad(`bundles 里列了但 dependencies 里没有：${orphan.join(', ')} —— DSH 会解析不到该 bundle 而启动失败`);
      console.log('      修法：从 package.json 的 dsh.profile.bundles 里移除它，或把依赖加回去');
    } else if (notBundled.length) {
      warn(`依赖里有但未列入 bundles：${notBundled.join(', ')} —— 不会作为 profile 层自动激活（需用 --patch 或 insert）`);
    } else if (bl.some((b) => b.startsWith('@vmprobe'))) {
      ok('vmprobe 已在 dependencies 与 bundles 中成对出现（`dsh plugin add` 的正确结果）');
    } else {
      console.log('      profile 未安装 vmprobe（无一致性可查）');
    }
  }
}

console.log('\n[4] 本机 DSH 进程与端口');
const { execSync } = await import('node:child_process');
try {
  const out = execSync('netstat -ano -p tcp', { encoding: 'utf8' });
  const line = out.split('\n').find((l) => /:3080\b/.test(l) && /LISTENING/i.test(l));
  if (line) {
    const pid = line.trim().split(/\s+/).pop();
    ok(`3080 正在监听（PID ${pid}）—— 这是活实例，测试请用 --port 0 另起，不要动它`);
  } else {
    warn('3080 没有监听（DSH 当前未运行）');
  }
} catch { warn('无法查询端口状态'); }

console.log(`\n${
  problems === 0
    ? `预检通过 ✔${warnings ? `（另有 ${warnings} 项警告，见上）` : ''}`
    : `发现 ${problems} 个会阻塞启动的问题 ✖${warnings ? `（另有 ${warnings} 项警告）` : ''}`
}\n`);
process.exit(problems === 0 ? 0 : 1);
