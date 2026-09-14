/**
 * 动作目录加载器 —— 严格校验（DESIGN.md §5.3 / §13）。
 *
 * 设计原则：**未知字段直接报错，而不是静默忽略**。
 * 理由：动作目录是安全边界的一部分。如果 `risk` 拼错成 `Risk` 而加载器静默忽略，
 * 动作会以默认 R1 运行 —— 一个本该 R3 的动作被降级执行，且没有任何提示。
 * 宁可启动失败，也不要静默降级安全属性。
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const RISKS = new Set(['R0', 'R1', 'R2', 'R3', 'dynamic']);
const SIDES = new Set(['agent', 'controller']);

const ALLOWED_KEYS = new Set([
  'id', 'version', 'side', 'title', 'summary', 'risk', 'params', 'requires',
  'idempotent', 'timeoutMs', 'check', 'apply', 'verify', 'rollback', 'notes',
  /** 已接线的参数名清单。未列出的参数一出现即 fail-closed 阻断（防"谎报行为"）。 */
  'wiredParams',
]);

/** 必填字段。 */
const REQUIRED = ['id', 'version', 'side', 'title', 'summary', 'risk', 'apply'];

/**
 * 校验一个 argv 元素，并收集它引用到的参数名。
 *
 * argv 元素支持三种写法（见 `core/src/plan.js` 的 `resolveCommands`）：
 *   · 字符串                     `"--noconfirm"`（可含 `{{name}}` 插值）
 *   · 参数替换                   `{"$param":"exclude","prefix":"--exclude="}`
 *   · 条件参数                   `{"$when":"securityOnly","argv":["--security"]}`
 *
 * ★ 顺带做一件很重要的事：**校验引用的参数名确实在 `params.properties` 里声明过**。
 *   否则把 `$param` 写成 `exclude2` 不会报错，只会让该参数"看起来接线了、实际没接" ——
 *   而 fail-closed 会把它拦下，作者却看到一句莫名其妙的"尚未接线"。
 */
function validateArgvElement(el, source, declared, referenced, where) {
  if (typeof el === 'string') {
    for (const m of el.matchAll(/\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g)) {
      referenced.add(m[1]);
      if (!declared.includes(m[1])) {
        throw new Error(`${source}: ${where} 里的 {{${m[1]}}} 引用了未声明的参数`);
      }
    }
    return;
  }
  if (el === null || typeof el !== 'object' || Array.isArray(el)) {
    throw new Error(`${source}: ${where} 的 argv 元素必须是字符串或 {$param}/{$when} 对象`);
  }
  if ('$param' in el) {
    const extra = Object.keys(el).filter((k) => k !== '$param' && k !== 'prefix');
    if (extra.length) throw new Error(`${source}: ${where} 的 $param 元素含未知字段 ${extra.join(', ')}`);
    if (typeof el.$param !== 'string' || !el.$param) {
      throw new Error(`${source}: ${where} 的 $param 必须是非空字符串`);
    }
    if (el.prefix !== undefined && typeof el.prefix !== 'string') {
      throw new Error(`${source}: ${where} 的 prefix 必须是字符串`);
    }
    referenced.add(el.$param);
    if (!declared.includes(el.$param)) {
      throw new Error(`${source}: ${where} 引用了未声明的参数 $${el.$param}`);
    }
    return;
  }
  if ('$when' in el) {
    const extra = Object.keys(el).filter((k) => k !== '$when' && k !== 'argv');
    if (extra.length) throw new Error(`${source}: ${where} 的 $when 元素含未知字段 ${extra.join(', ')}`);
    if (typeof el.$when !== 'string' || !el.$when) {
      throw new Error(`${source}: ${where} 的 $when 必须是非空字符串`);
    }
    if (!Array.isArray(el.argv) || el.argv.length === 0) {
      throw new Error(`${source}: ${where} 的 $when.argv 必须是非空数组（没内容就不该写 $when）`);
    }
    referenced.add(el.$when);
    if (!declared.includes(el.$when)) {
      throw new Error(`${source}: ${where} 引用了未声明的参数 $${el.$when}`);
    }
    el.argv.forEach((inner, i) => validateArgvElement(inner, source, declared, referenced, `${where}.$when.argv[${i}]`));
    return;
  }
  throw new Error(`${source}: ${where} 的 argv 元素对象必须含 $param 或 $when`);
}

/** 校验一个 argv 数组（一个命令）。 */
function validateArgv(argv, source, declared, referenced, where) {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new Error(`${source}: ${where} 必须是非空 argv 数组`);
  }
  argv.forEach((el, i) => validateArgvElement(el, source, declared, referenced, `${where}[${i}]`));
}

/**
 * 校验单条动作定义。
 * @throws {Error} 任何不合规都抛错，并指出具体字段。
 */
export function validateAction(action, source = '<inline>') {
  if (action === null || typeof action !== 'object' || Array.isArray(action)) {
    throw new Error(`${source}: 动作定义必须是对象`);
  }

  for (const key of Object.keys(action)) {
    if (!ALLOWED_KEYS.has(key)) {
      throw new Error(
        `${source}: 未知字段 "${key}"。` +
        '动作定义是安全边界，拼错字段会导致风险级被静默降级，因此拒绝加载。',
      );
    }
  }

  for (const key of REQUIRED) {
    if (action[key] === undefined) throw new Error(`${source}: 缺少必填字段 "${key}"`);
  }

  if (!/^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$/.test(action.id)) {
    throw new Error(`${source}: id "${action.id}" 必须是小写点分标识（如 system.update）`);
  }
  if (!Number.isInteger(action.version) || action.version < 1) {
    throw new Error(`${source}: version 必须是 ≥1 的整数`);
  }
  if (!SIDES.has(action.side)) {
    throw new Error(`${source}: side 必须是 ${[...SIDES].join(' | ')}，实际 "${action.side}"`);
  }
  if (!RISKS.has(action.risk)) {
    throw new Error(`${source}: risk 必须是 ${[...RISKS].join(' | ')}，实际 "${action.risk}"`);
  }
  if (!action.title || typeof action.title.zh !== 'string' || !action.title.zh) {
    throw new Error(`${source}: title.zh 必须是非空字符串`);
  }

  // apply 至少要有一个分支，否则动作无法执行
  if (action.apply === null || typeof action.apply !== 'object' || Array.isArray(action.apply)) {
    throw new Error(`${source}: apply 必须是 { distroKey: { pre?, cmd, env? } } 对象`);
  }
  const branches = Object.keys(action.apply);
  if (branches.length === 0) throw new Error(`${source}: apply 必须至少有一个发行版分支`);

  const declaredParams = Object.keys(action.params?.properties ?? {});
  const referenced = new Set();

  for (const key of branches) {
    const branch = action.apply[key];
    if (branch === null || typeof branch !== 'object') {
      throw new Error(`${source}: apply.${key} 必须是对象`);
    }

    if (action.side === 'controller') {
      // controller 侧动作**不得**声明远端 argv。
      // 推演发现 F1/F10：原来它带着一个 "vmprobe auth …" 的假命令，
      // 会被当成远端 shell 下发 —— 命令不存在，语义也完全错。
      if (branch.cmd !== undefined) {
        throw new Error(
          `${source}: side=controller 的 apply.${key} 不允许有 cmd。` +
          'controller 侧动作在主控端本地执行，应声明 handler（处理函数标识）。',
        );
      }
      if (typeof branch.handler !== 'string' || !branch.handler) {
        throw new Error(`${source}: side=controller 的 apply.${key} 必须声明 handler（字符串标识）`);
      }
      continue;
    }

    if (typeof branch.handler === 'string') {
      throw new Error(`${source}: side=agent 的 apply.${key} 不允许有 handler（应为 cmd）`);
    }
    if (!Array.isArray(branch.cmd) || branch.cmd.length === 0) {
      throw new Error(`${source}: apply.${key}.cmd 必须是非空 argv 数组的数组`);
    }
    const branchExtra = Object.keys(branch).filter((k) => !['pre', 'cmd', 'env', 'dryRun'].includes(k));
    if (branchExtra.length) {
      throw new Error(`${source}: apply.${key} 含未知字段 ${branchExtra.join(', ')}（只允许 pre/cmd/env/dryRun）`);
    }

    (branch.pre ?? []).forEach((argv, i) => validateArgv(argv, source, declaredParams, referenced, `apply.${key}.pre[${i}]`));
    branch.cmd.forEach((argv, i) => validateArgv(argv, source, declaredParams, referenced, `apply.${key}.cmd[${i}]`));
    if (branch.dryRun !== undefined) {
      branch.dryRun.forEach((argv, i) => validateArgv(argv, source, declaredParams, referenced, `apply.${key}.dryRun[${i}]`));
    }
  }

  // verify（M2-①）也要严格校验：它决定"事后怎么判定成功"，
  // 写错会得到一个看起来通过了、其实什么都没验证的动作。
  if (action.verify !== undefined) {
    const v = action.verify;
    const where = `${source}: verify`;
    if (v === null || typeof v !== 'object' || Array.isArray(v)) {
      throw new Error(`${where} 必须是对象（{ probe, expect?, maxWaitMs? }）`);
    }
    const extra = Object.keys(v).filter((k) => !['probe', 'expect', 'maxWaitMs'].includes(k));
    if (extra.length) throw new Error(`${where} 含未知字段 ${extra.join(', ')}（只允许 probe/expect/maxWaitMs）`);
    if (typeof v.probe !== 'string' || !v.probe) {
      throw new Error(`${where}.probe 必须是非空字符串`);
    }
    if (v.expect !== undefined) {
      if (v.expect === null || typeof v.expect !== 'object' || Array.isArray(v.expect)) {
        throw new Error(`${where}.expect 必须是对象（字段名 → 期望值）`);
      }
      for (const [key, val] of Object.entries(v.expect)) {
        const okScalar = val === null || ['boolean', 'number', 'string'].includes(typeof val);
        const okArray = Array.isArray(val)
          && val.every((x) => x === null || ['boolean', 'number', 'string'].includes(typeof x));
        if (!okScalar && !okArray) {
          throw new Error(
            `${where}.expect.${key} 只能是标量或标量数组 —— `
            + '深层结构会让"是否达到目标态"变得无法一目了然，拒绝加载',
          );
        }
      }
    }
    if (v.maxWaitMs !== undefined) {
      if (!Number.isInteger(v.maxWaitMs) || v.maxWaitMs < 0) {
        throw new Error(`${where}.maxWaitMs 必须是 ≥0 的整数`);
      }
    }
  }

  // wiredParams 是 M1 之前的静态声明，现在由 argv 用法自动推导（见 core/plan.js）。
  // 保留字段只为兼容旧定义，**内容被忽略**；这里若出现"声明了却没被引用"的名字，直接报错，
  // 免得作者以为它还在起作用。
  if (action.wiredParams !== undefined) {
    if (!Array.isArray(action.wiredParams) || action.wiredParams.some((k) => typeof k !== 'string')) {
      throw new Error(`${source}: wiredParams 必须是字符串数组`);
    }
    const stale = action.wiredParams.filter((k) => !referenced.has(k));
    if (stale.length) {
      throw new Error(
        `${source}: wiredParams 里的 ${stale.join('、')} 并未被任何 argv 引用 —— `
        + '该字段已废弃（接线由 argv 用法自动推导），请删掉它；'
        + '若确实想接线，请在命令里用 {"$param":…} / {"$when":…} / {{name}} 引用该参数。',
      );
    }
  }

  // wiredParams 必须是 params 里声明过的键，否则是拼写错误
  if (action.wiredParams !== undefined) {
    if (!Array.isArray(action.wiredParams) || action.wiredParams.some((k) => typeof k !== 'string')) {
      throw new Error(`${source}: wiredParams 必须是字符串数组`);
    }
    const declared = Object.keys(action.params?.properties ?? {});
    for (const key of action.wiredParams) {
      if (!declared.includes(key)) {
        throw new Error(`${source}: wiredParams 里的 "${key}" 未在 params.properties 中声明`);
      }
    }
  }

  // dynamic 风险必须有 check，否则运行时无从判定
  if (action.risk === 'dynamic' && !action.check) {
    throw new Error(`${source}: risk 为 dynamic 时必须声明 check（运行时提权依据来自它）`);
  }

  return action;
}

/**
 * 从目录加载全部动作定义。
 *
 * **同步**实现：插件 `apply()` 需要在初始化期就拿到目录（用于注册工具与同步校验），
 * 而动作文件是极小的 JSON，同步读取代价可忽略。
 *
 * @param {string} dir
 * @returns {{ actions: Map<string, object>, sources: Map<string, string> }}
 */
export function loadCatalog(dir) {
  const actions = new Map();
  const sources = new Map();

  let files;
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  } catch (err) {
    if (err && err.code === 'ENOENT') return { actions, sources };
    throw err;
  }

  for (const file of files) {
    const full = join(dir, file);
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(full, 'utf8'));
    } catch (err) {
      throw new Error(`${file}: JSON 解析失败 —— ${err.message}`);
    }
    validateAction(parsed, file);
    if (actions.has(parsed.id)) {
      throw new Error(`动作 id 重复: ${parsed.id}（${sources.get(parsed.id)} 与 ${file}）`);
    }
    actions.set(parsed.id, parsed);
    sources.set(parsed.id, file);
  }

  return { actions, sources };
}

/** 列出目录摘要（给 vmprobe_catalog 工具用）。 */
export function listCatalog(actions) {
  return [...actions.values()]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((a) => ({
      id: a.id,
      version: a.version,
      side: a.side,
      title: a.title.zh,
      summary: a.summary,
      risk: a.risk,
      distros: Object.keys(a.apply),
    }));
}
