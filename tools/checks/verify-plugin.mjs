/**
 * 插件契约与行为验证 —— 直接 import 插件模块，在 mock ctx 上跑 apply()，
 * 检查它是否满足 DSH 的函数插件契约，并逐个校验注册的工具定义。
 *
 * 验证的是「我的代码对不对」；「Loader 能不能加载它」由真机启动验证
 * （见 tools/checks/ssh-transport.mjs 之外的启动流程、以及 README 的排查章节）。
 *
 *   node tools/checks/verify-plugin.mjs
 */

import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { tryImportDshPackage } from '../lib/dsh-runtime.mjs';

const mod = await import('../../packages/plugin-host/src/index.js');

/**
 * 直接加载 **DSH 自己的 schema 校验器**来校验我们的工具定义。
 *
 * 为什么必须有这一步：真机启动时踩过一次 —— `output.schema` 里写了 `type: ['string','null']`，
 * 而 DSH 只支持**单个标量 type**（可空要用 `oneOf`），于是那条 entry 加载失败、
 * **整棵插件树加载不出来**。当时本脚本只验了"output.schema 是个对象"，查不出来。
 * 现在直接用宿主的校验器，把"启动才发现"提前到"检查阶段就发现"。
 *
 * 解析方式已改为**可移植探测**（技术债 #10）：原来写死了本机绝对路径，
 * 换机器/换 Node 版本/DSH 升级后全都会以"模块找不到"失败。
 */
const dshTools = await (async () => {
  const mod = await tryImportDshPackage('@deepseek-ai/dsh-tools');
  if (!mod) return null;
  // 命名导出在模块**顶层**（`default` 是 DSH 的插件函数，不是这些校验器）。
  // 踩过一次：写成 `mod.default ?? mod` 后拿到的是插件函数，于是
  // `validateJsonSchemaValue is not a function` —— 而"回退链写成什么"本身
  // 就不该靠猜，所以这里显式挑带校验器的那个。
  if (typeof mod.validateJsonSchemaValue === 'function' || typeof mod.assertSupportedJsonSchema === 'function') {
    return mod;
  }
  return mod.default ?? mod;
})();

let failures = 0;
const check = (label, fn) => {
  try {
    fn();
    console.log(`  ✔ ${label}`);
  } catch (err) {
    failures++;
    console.log(`  ✖ ${label}\n      ${err.message}`);
  }
};

console.log('\n[1] 模块契约（DSH 函数插件约定）');
check('有 name 导出', () => assert.equal(typeof mod.name, 'string'));
check('有 apply 导出', () => assert.equal(typeof mod.apply, 'function'));
check('有 inject 导出且为数组', () => assert.ok(Array.isArray(mod.inject)));
check('inject 含 tools（核心必需）', () => {
  assert.ok(mod.inject.includes('tools'), 'inject 必须含 tools');
});
check('★ inject **不含** approval（I5 决策：加载不阻塞，执行时 fail-closed）', () => {
  assert.ok(
    !mod.inject.includes('approval'),
    'approval 若留在 inject 里，缺审批服务的 profile 中 apply() 根本不会执行 —— '
    + '一个可选服务的缺失不该导致插件（乃至整棵插件树）加载失败。'
    + '安全性由执行时的 fail-closed 保证，见 [7]。',
  );
});
check('**没有 default 导出**（否则 Loader 会丢掉 inject）', () => {
  assert.equal(mod.default, undefined, 'default 导出会让 unwrapExports 折叠模块');
});

console.log('\n[2] apply() 在 mock ctx 上注册工具');
const registered = [];
const logs = [];
const injectedDeps = [];
const scheduledTicks = [];
let directIntervalCalls = 0;

/**
 * mock ctx 同时提供 `inject` 与 `interval`，用来守住一个**实测抓到的真 bug**：
 * 原来直接调 `ctx.interval`，但插件没 inject 'timer'，于是 apply() 可能跑在
 * timer 服务就绪之前 → 定时器压根没注册、且没有任何报错（生产表现为"日报永远不出现"）。
 * 正确做法是用 `ctx.inject(['timer'], cb)` 等依赖就绪。
 */
const makeChildCtx = () => ({
  logger: { info: (m) => logs.push(['info', m]), warn: (m) => logs.push(['warn', m]) },
  interval: (fn, ms) => { scheduledTicks.push(ms); return () => {}; },
});

const mockCtx = {
  tools: {
    register(def) {
      registered.push(def);
      return () => {};
    },
  },
  approval: {
    async request() {
      return 'allowed-once';
    },
  },
  logger: {
    info: (m) => logs.push(['info', m]),
    warn: (m) => logs.push(['warn', m]),
  },
  // 外层 ctx 也提供 interval：如果插件直接用它，计数器就会非 0 → 测试失败
  interval: () => { directIntervalCalls++; return () => {}; },
  inject(deps, cb) {
    injectedDeps.push(deps);
    cb(makeChildCtx()); // 模拟"依赖就绪后执行回调"
    return Promise.resolve();
  },
};

const stateDir = await mkdtemp(join(tmpdir(), 'vmprobe-m0-'));
try {
  mod.apply(mockCtx, {
    storageDir: stateDir,
    // 契约测试刻意**不接传输层**：它不该依赖网络，也不该因为连不上某个虚构主机而变慢或报错。
    // 生产默认会自动创建 SSH 传输层（见 index.js），这里显式关掉。
    transport: null,
  });

  check('apply() 未抛异常', () => {});
  check('注册了 6 个工具', () => assert.equal(registered.length, 6, `实际 ${registered.length}`));

  const names = registered.map((t) => t.name).sort();
  check('工具名与设计一致', () => {
    assert.deepEqual(names, [
      'vmprobe_action',
      'vmprobe_catalog',
      'vmprobe_facts',
      'vmprobe_logs',
      'vmprobe_status',
      'vmprobe_targets',
    ]);
  });

  // 守住"容器依赖顺序"这一类静默故障（实测抓到过：定时器从未注册且无报错）
  check('定时器经 ctx.inject([\'timer\']) 获取，而非直接调 ctx.interval', () => {
    assert.ok(injectedDeps.length > 0, 'apply() 没有调用 ctx.inject');
    assert.deepEqual(injectedDeps[0], ['timer'], '应显式等待 timer 依赖');
    assert.equal(directIntervalCalls, 0,
      '不应直接在外层 ctx 上调 interval —— 那时 timer 服务可能还没就绪，定时器会静默不注册');
  });
  check('依赖就绪后确实注册了定时 tick（心跳 + 日报各一）', () => {
    assert.equal(scheduledTicks.length, 2, `期望 2 个 tick（心跳/日报），实际 ${scheduledTicks.length}`);
    // 顺序：先心跳（观测），后日报（业务）
    assert.deepEqual(scheduledTicks, [60000, 60000], `tick 间隔应为 60s，实际 ${JSON.stringify(scheduledTicks)}`);
  });

  console.log('\n[3] 每个工具定义必须满足 ToolDefinition');
  for (const def of registered) {
    check(`${def.name}: name/description/parameters 齐备`, () => {
      assert.equal(typeof def.name, 'string');
      assert.ok(def.description && def.description.length > 10, 'description 太短，模型难以选用');
      assert.equal(typeof def.parameters, 'object');
      assert.equal(def.parameters.type, 'object');
    });
    check(`${def.name}: execute 是函数`, () => assert.equal(typeof def.execute, 'function'));
    // 这是 M0 核实到的硬要求：output 是必填，且 render 必须返回 ContentBlock[]
    check(`${def.name}: 声明了必填的 output.schema`, () => {
      assert.ok(def.output, 'ToolDefinition.output 是必填字段');
      assert.equal(typeof def.output.schema, 'object');
    });
    check(`${def.name}: output.render 是函数`, () => {
      assert.equal(typeof def.output.render, 'function');
    });
    if (def.presentCall) {
      check(`${def.name}: presentCall 返回 card 标签的视图`, () => {
        const view = def.presentCall({});
        if (view === undefined) return; // 允许返回 undefined 走通用渲染
        assert.ok(['generic', 'terminal', 'diff'].includes(view.card), `非法 card: ${view.card}`);
        assert.equal(typeof view.title, 'string');
      });
    }
    // ★ 用宿主自己的校验器验 schema 子集 —— 这一类错误只有启动时才会暴露，
    //   而一条 entry 失败会让整棵插件树加载不出来，所以必须在这里拦住。
    check(`${def.name}: output.schema 落在 DSH 支持的 JSON Schema 子集内`, () => {
      if (!dshTools) return; // 找不到宿主校验器时跳过（下面会告警）
      dshTools.assertSupportedJsonSchema(def.output.schema);
      dshTools.assertObjectJsonSchema(def.output.schema);
    });
    check(`${def.name}: parameters 落在 DSH 支持的 JSON Schema 子集内`, () => {
      if (!dshTools) return;
      dshTools.assertSupportedJsonSchema(def.parameters);
    });
  }

  console.log('\n[4] 工具可实际调用（只读路径）');
  const byName = Object.fromEntries(registered.map((t) => [t.name, t]));
  const fakeExec = { callId: 'call_1', signal: new AbortController().signal, agent: { id: 'agent_1' } };

  /**
   * 用**真实 execute 返回值**驱动 render。
   * 契约是 render(args, value) 里的 value 已经过 output.schema 校验，
   * 所以用空值调用它并不能说明问题 —— 必须用真值。
   */
  const rendered = [];
  const callAndRender = async (toolName, args) => {
    const def = byName[toolName];
    const value = await def.execute(args, fakeExec);
    // ★ 用宿主自己的值校验器确认"实际返回值确实符合声明的 output.schema"
    //   （DSH 运行时就是这么做的，schema 与实现不一致属于真 bug）
    if (dshTools) dshTools.validateJsonSchemaValue(def.output.schema, JSON.parse(JSON.stringify(value)), 'value');
    const out = def.output.render(args, value);
    assert.ok(Array.isArray(out), `${toolName} 的 render 必须返回数组`);
    for (const block of out) {
      assert.equal(block.type, 'text', `${toolName} 的 render 只应产出 text 块`);
      assert.equal(typeof block.text, 'string');
      assert.ok(block.text.length > 0, `${toolName} 的 render 产出了空文本`);
    }
    rendered.push([toolName, out[0].text]);
    return value;
  };

  const cat = await callAndRender('vmprobe_catalog', {});
  check('vmprobe_catalog 返回动作清单与用法提示', () => {
    assert.equal(cat.actions.length, 4, `实际 ${cat.actions.length} 个动作`);
    assert.match(cat.usage, /VMProbe 基础用法/);
  });

  const st = await callAndRender('vmprobe_status', {});
  check('vmprobe_status 如实报告"未接线"（不再硬编码一个像真状态的 detached）', () => {
    assert.equal(st.canExecute, false);
    assert.equal(st.connectionState, 'not-wired');
    assert.equal(st.audit.ok, true);
  });

  // 端到端走一遍：加目标 → 计划 R2 动作 → 因未接线而停在 not_implemented（不应浪费一次审批）
  const added = await callAndRender('vmprobe_targets', {
    op: 'add', id: 't_m0', label: 'vm-m0', hostname: '10.0.0.5', user: 'ops',
    authRef: 'vault://vm-m0/login', tags: ['prod'],
  });
  check('vmprobe_targets 可添加目标（凭据只留引用）', () => {
    assert.equal(added.target.id, 't_m0');
    assert.equal(added.target.authRef.kind, 'password');
    assert.ok(!('password' in added.target), '目标记录不得含 password 字段');
  });
  await callAndRender('vmprobe_targets', { op: 'list' });

  let approvalAsked = 0;
  mockCtx.approval.request = async () => {
    approvalAsked++;
    return 'allowed-once';
  };

  const act = await callAndRender('vmprobe_action', {
    target: 'vm-m0', action: 'ssh.passwordless.enable',
  });
  check('R3 动作：计划生成、风险识别为 R3', () => {
    assert.equal(act.plan.risk, 'R3');
    assert.equal(act.plan.requireEchoHostname, true);
  });
  // 本测试刻意不接传输层，于是 check 探测不到任何状态 → 计划无法验证新鲜度 → fail-closed。
  // 关键不变式是"**没有浪费一次用户审批**、也没有执行"，而不是某个具体状态词 ——
  // 所以这里断言这两条，避免措辞变化就把测试改松。
  check('无传输层时拒绝执行，且**没有浪费一次用户审批**', () => {
    assert.notEqual(act.status, 'ok', '不应执行');
    assert.equal(approvalAsked, 0, `不应发起审批，实际发起了 ${approvalAsked} 次`);
    assert.ok(act.error && act.error.length > 0, '必须给出明确原因');
    assert.ok(['stale', 'not_implemented', 'blocked'].includes(act.status),
      `状态应是显式拒绝之一，实际 ${act.status}`);
  });

  const logsOut = await callAndRender('vmprobe_logs', { limit: 5 });
  check('vmprobe_logs 能看到审计事件且链完好', () => {
    assert.ok(logsOut.total > 0);
    assert.equal(logsOut.chain.ok, true);
    assert.ok(logsOut.events.some((e) => e.event === 'action.plan'));
  });

  console.log('\n[5] 真实结果经 render 后的模型可见文本');
  for (const [toolName, txt] of rendered) {
    console.log(`  ── ${toolName} ──`);
    console.log(txt.split('\n').map((l) => `     ${l}`).join('\n'));
  }

  console.log('\n[6] 插件日志输出');
  for (const [level, msg] of logs) console.log(`  [${level}] ${msg}`);
} finally {
  await rm(stateDir, { recursive: true, force: true });
}

// ===========================================================================
// [7] I5：**没有审批服务时**的行为 —— 插件必须照样加载，且 R2/R3 一律拒绝
//
// 这一节守的是一个安全属性 + 一个可用性属性，两者都不能丢：
//   · 可用性：缺 approval 不能导致插件加载失败（否则一个可选服务就能让整棵树起不来）
//   · 安全：  缺 approval 时**绝不能**执行 R2/R3（fail-closed）
// 上一版把 approval 放在 inject 里靠"不加载"来保证安全 —— 代价太大，这里改成运行时守。
// ===========================================================================
console.log('\n[7] I5：缺少审批服务时的加载与执行行为');

{
  const noApprovalDir = await mkdtemp(join(tmpdir(), 'vmprobe-noapproval-'));
  const registeredNoApproval = [];
  const logsNoApproval = [];
  /**
   * 假传输层：**只做一件事** —— 让"计划新鲜度"这一关能过，
   * 这样 R3 才会走到**审批那一关**，测到的才是审批护栏而不是别的护栏。
   * （第一版这里用 `transport: null`，结果 R3 停在 `stale`，根本没碰到审批 ——
   *   断言"被拒绝"会通过，但拒绝的原因完全不是我以为的那个。）
   * 同时记录 apply 次数：缺审批时它必须是 **0**（一行都没执行）。
   */
  const i5Transport = {
    applyCalls: 0,
    async state() { return 'connected'; },
    async check() {
      return { probed: true, pubkeyAuth: true, passwordAuth: true, port: 22, serviceKeyInstalled: false };
    },
    async apply() { i5Transport.applyCalls += 1; return { exit: 0 }; },
    async heartbeat() { return { ok: true, at: new Date().toISOString(), latencyMs: 1 }; },
  };
  const noApprovalCtx = {
    tools: { register(def) { registeredNoApproval.push(def); return () => {}; } },
    // 刻意**不提供** approval
    logger: { info: (m) => logsNoApproval.push(['info', m]), warn: (m) => logsNoApproval.push(['warn', m]) },
    inject: () => {},
  };

  try {
    let loadError = null;
    try {
      mod.apply(noApprovalCtx, {
        storageDir: noApprovalDir,
        transport: i5Transport,          // 有传输层 → 新鲜度可通过 → 才会走到审批护栏
        dailyReport: false,
        loadMarkerFile: join(noApprovalDir, 'loads.jsonl'),
      });
    } catch (err) {
      loadError = err;
    }

    check('★ 没有 approval 时插件仍能加载（apply 不抛错）', () => {
      assert.equal(loadError, null, `apply 抛错了：${loadError?.message}`);
    });
    check('★ 没有 approval 时工具照样全部注册', () => {
      assert.equal(registeredNoApproval.length, 6, `应注册 6 个工具，实际 ${registeredNoApproval.length}`);
    });
    check('没有 approval 时明确告警（不静默）', () => {
      const warned = logsNoApproval.some(([lvl, m]) => lvl === 'warn' && /审批服务/.test(m));
      assert.ok(warned, `应有审批服务不可用的告警，实际日志：${JSON.stringify(logsNoApproval)}`);
    });
    check('加载台账记下 approval.unavailable', () => {
      const ledger = readFileSync(join(noApprovalDir, 'loads.jsonl'), 'utf8');
      assert.ok(ledger.includes('"approval.unavailable"'), '台账里应有 approval.unavailable 事件');
      assert.ok(ledger.includes('"load"'), '仍然要有 load 事件');
    });

    // ── 执行侧：R0 可用、R2/R3 必须被拒 ──────────────────────────────────
    const statusTool = registeredNoApproval.find((d) => d.name === 'vmprobe_status');
    const actionTool = registeredNoApproval.find((d) => d.name === 'vmprobe_action');
    const targetsTool = registeredNoApproval.find((d) => d.name === 'vmprobe_targets');
    const execCtx = { callId: 'c1', signal: new AbortController().signal, arguments: {} };

    // 先加一个目标（否则动作会因为"目标不存在"而失败，测不到审批这一层）
    await targetsTool.execute(
      { op: 'add', id: 't_i5', hostname: '10.0.0.9', user: 'ops', authRef: 'VMPROBE_I5_PASSWORD' },
      execCtx,
    );

    const status = await statusTool.execute({}, execCtx);
    check('状态工具如实报告"审批不可用"', () => {
      assert.equal(status.approvalAvailable, false);
      assert.ok(
        status.warnings.some((w) => /审批服务/.test(w)),
        '状态里的警告应包含审批不可用',
      );
    });

    // R0 动作（probe.facts，controller 侧；这里没有传输层，预期走到"未实现"而不是"被审批拒绝"）
    const r0 = await actionTool.execute({ target: 't_i5', action: 'probe.facts' }, execCtx).catch((e) => ({ threw: e }));
    check('R0/R1 动作**不会**因为缺审批被拒（缺的是传输层，不是审批）', () => {
      const asText = JSON.stringify(r0);
      assert.ok(
        !/审批服务不可用/.test(asText),
        `R0 动作不应被审批拦下，实际：${asText.slice(0, 200)}`,
      );
    });

    // R3 动作（免密登录）：必须被 fail-closed 拒绝
    const r3 = await actionTool.execute({ target: 't_i5', action: 'ssh.passwordless.enable' }, execCtx);
    check('★ R3 动作在缺审批时被 fail-closed 拒绝执行', () => {
      assert.equal(r3?.status, 'blocked', `R3 应被阻断，实际 status=${r3?.status}（若为 stale 说明没走到审批这一关）`);
      assert.match(String(r3?.error ?? ''), /审批服务不可用/, '拒绝原因必须点明是审批服务不可用');
    });
    check('★ 被拒时**一行都没执行**（transport.apply 调用次数为 0）', () => {
      assert.equal(i5Transport.applyCalls, 0, `apply 被调用了 ${i5Transport.applyCalls} 次 —— 护栏漏了`);
    });
    check('被拒时不谎报成功（没有 result/verify）', () => {
      assert.equal(r3.verify ?? null, null, '被拒绝的执行不应产生校验结论');
      assert.equal(r3.run ?? null, null, '被拒绝的执行不应产生运行记录');
    });

    console.log('\n[8] 无审批服务时的日志');
    for (const [level, msg] of logsNoApproval) console.log(`  [${level}] ${msg}`);
  } finally {
    await rm(noApprovalDir, { recursive: true, force: true });
  }
}

// ===========================================================================
// [9] I6：cordis 的上下文是 **Proxy** —— 读一个"已声明但未注入"的服务名会**抛异常**，
//      而不是返回 undefined。
//
// 这一节守的是"插件还起不起得来"：I5 把 approval 从 inject 里拿掉之后，apply() 里那句
// `ctx.approval &&` 自己就把整棵插件树带崩了（真机实测：
// `cannot get property "approval" without inject` → 整棵树加载失败）。
//
// 为什么 [7] 查不出来：它的 ctx 是**裸对象**，读不存在的字段只会得到 undefined ——
// 那正是我当时的假设。**用自己写的桩去验证假设，等于没验证**（§5.2 坑 14）。
// 所以这里造一个"像 cordis 那样说话"的 ctx：未注入的服务名一读就抛。
// ===========================================================================
console.log('\n[9] I6：模拟 cordis 代理语义（未注入的服务名会抛异常）');

{
  const dir = await mkdtemp(join(tmpdir(), 'vmprobe-proxy-'));
  const registered = [];
  const logs = [];
  const approvalRequests = [];
  const promptSections = [];
  const applyCalls = { n: 0 };

  /** 组合里**有**审批服务（web profile 的实际情况：dsh-base 里有 dsh-user-approval）。 */
  const provided = {
    approval: { async request(req) { approvalRequests.push(req); return 'allowed-once'; } },
    // 记录 prompt section 的注册参数 —— 用来守住"签名猜错了也没人发现"这类静默失效
    systemPrompt: { section(s) { promptSections.push(s); return () => {}; } },
  };

  /**
   * 假传输层：只为让"计划新鲜度"过关 —— 这样 R3 才会真的走到审批那一关。
   * 缺了它，R3 会停在 `stale`，断言"被拒绝"照样绿，但拒绝的原因不是审批（坑：断言了错的东西）。
   */
  const proxyTransport = {
    async state() { return 'connected'; },
    async check() {
      return { probed: true, pubkeyAuth: true, passwordAuth: true, port: 22, serviceKeyInstalled: false };
    },
    async apply() { applyCalls.n += 1; return { exit: 0 }; },
    async heartbeat() { return { ok: true, at: new Date().toISOString(), latencyMs: 1 }; },
  };

  const proxyCtx = {
    tools: { register(def) { registered.push(def); return () => {}; } },
    logger: { info: (m) => logs.push(['info', m]), warn: (m) => logs.push(['warn', m]) },
    // cordis 的正式读取入口：无注入要求，未提供即 undefined
    get: (name) => provided[name],
    inject: () => {},
  };
  // 复刻 cordis 的行为：**已声明但本 fiber 未注入**的服务名，一读就抛
  const UNINJECTED = ['approval', 'credentials', 'timer'];
  for (const name of UNINJECTED) {
    Object.defineProperty(proxyCtx, name, {
      get() { throw new Error(`cannot get property "${name}" without inject`); },
      configurable: true,
    });
  }

  try {
    // 先确认这个桩确实复刻了触发条件 —— 否则下面全是空转
    check('探测点有效：旧写法 `ctx.approval` 在这个 ctx 上会抛（这正是 I5 崩溃的原因）', () => {
      assert.throws(() => proxyCtx.approval, /without inject/);
    });

    let loadError = null;
    try {
      mod.apply(proxyCtx, {
        storageDir: dir,
        transport: proxyTransport,
        dailyReport: false,
        loadMarkerFile: join(dir, 'loads.jsonl'),
      });
    } catch (err) {
      loadError = err;
    }

    check('★ 该类上下文下 apply() 不抛错（I5 落地时就是在这里把整棵树带崩的）', () => {
      assert.equal(loadError, null, `apply 抛错了：${loadError?.message}`);
    });
    check('★ 工具照样全部注册', () => {
      assert.equal(registered.length, 6, `应注册 6 个工具，实际 ${registered.length}`);
    });
    check('审批服务**能通过 get 拿到**时如实记为可用（不误报不可用）', () => {
      const ledger = readFileSync(join(dir, 'loads.jsonl'), 'utf8');
      assert.ok(ledger.includes('"approval.available"'), '台账里应有 approval.available 事件');
      assert.ok(!ledger.includes('"approval.unavailable"'), '不该同时记 unavailable');
    });
    // 宿主对 section() 的要求（dsh-system-prompt/lib/types/index.d.ts:47 的 PromptSection）：
    // name 字符串 + order **有限数** + text 字符串或函数。非有限 order 直接抛 TypeError。
    // 此前写的是 { id, title, content } —— 三个字段全错，异常被 try/catch 吞成"不可用"告警，
    // 表现就像"宿主不支持"。这类"签名猜错"必须由探测点守住。
    check('★ systemPrompt.section 的注册参数形状正确（name / order / text）', () => {
      assert.equal(promptSections.length, 1, `应注册 1 个 prompt section，实际 ${promptSections.length}`);
      const s = promptSections[0];
      assert.equal(typeof s?.name, 'string', 'name 必须是字符串');
      assert.ok(Number.isFinite(s?.order), `order 必须是有限数，实际 ${JSON.stringify(s?.order)}`);
      assert.ok(
        typeof s?.text === 'string' || typeof s?.text === 'function',
        'text 必须是字符串或函数',
      );
    });

    const statusTool = registered.find((d) => d.name === 'vmprobe_status');
    const targetsTool = registered.find((d) => d.name === 'vmprobe_targets');
    const actionTool = registered.find((d) => d.name === 'vmprobe_action');
    const execCtx = { callId: 'c-i6', signal: new AbortController().signal, arguments: {}, agent: { sessionId: 's-i6' } };

    // 加目标会走 credentialState → 读 credentials（这里它是"未注入即抛"的）
    const added = await targetsTool.execute(
      { op: 'add', id: 't_i6', hostname: '10.0.0.10', user: 'ops', authRef: 'VMPROBE_I6_PASSWORD' },
      execCtx,
    ).catch((err) => ({ threw: err }));
    check('★ credentials 不可用时**不抛异常**，而是如实说"凭据状态未知"', () => {
      assert.ok(!added?.threw, `不应抛异常：${added?.threw?.message}`);
      const st = added?.target?.credential ?? added?.credential ?? null;
      if (st) assert.equal(st.known, false, '取不到凭据服务时必须是 known:false，不能假装知道');
    });

    const status = await statusTool.execute({}, execCtx);
    check('状态工具报告"审批可用"（与真机一致）', () => {
      assert.equal(status.approvalAvailable, true);
      assert.ok(
        !status.warnings.some((w) => /审批服务/.test(w)),
        `审批可用时不该有审批警告：${JSON.stringify(status.warnings)}`,
      );
    });

    // R3：审批可用 → 应当**真的发起一次审批**，然后被 echoHostname 护栏挡在执行之前
    const r3 = await actionTool.execute({ target: 't_i6', action: 'ssh.passwordless.enable' }, execCtx);
    check('★ R3 经新读取路径真的发起了审批（走通了 approval 这一关）', () => {
      assert.equal(approvalRequests.length, 1, `应发起 1 次审批，实际 ${approvalRequests.length}`);
      assert.match(String(approvalRequests[0]?.reason ?? ''), /R3/, '审批理由应点明风险级');
    });
    check('★ "审批通过"≠"可以执行"：即使用户批准，未实现的确认环节仍阻断', () => {
      assert.equal(r3?.status, 'blocked', `应被阻断，实际 status=${r3?.status}`);
      assert.equal(applyCalls.n, 0, `被阻断时一行都不该执行，实际执行了 ${applyCalls.n} 次`);
    });

    console.log('\n[10] 该类上下文下的插件日志');
    for (const [level, msg] of logs) console.log(`  [${level}] ${msg}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// ===========================================================================
// [11] 真实 cordis 运行时 —— "真机那一步"的本地替身
//
// 为什么 [9] 还不够：[9] 的桩**是我写的**，用自己写的桩去验证自己对宿主语义的理解，
// 等于没验证（§5.2 坑 14）。这一节直接拿 DSH 自带的 cordis 起一棵最小插件树：
// 服务由**兄弟** fiber 提供（复刻"approval 在 dsh-base 里、VMProbe 没注入它"的现场），
// 而 VMProbe 就是第三个兄弟 —— 崩与不崩，这次是真的由宿主的 Proxy 决定的。
//
// 这一段可以在沙箱里跑；**真机启动**（`dsh --profile web --no-open --port 0`）仍有独立价值
// ——它验证的是 Loader 组装与 profile 组合，本脚本代替不了（§5.2 坑 1）。
// ===========================================================================
console.log('\n[11] 真实 cordis：兄弟 entry 提供服务、VMProbe 未注入它');

const cordis = await tryImportDshPackage('@deepseek-ai/cordis');

if (!cordis?.Context || typeof cordis.Service !== 'function') {
  console.log('  ⚠ 取不到 DSH 自带的 cordis —— 本节**跳过**（跳过不等于通过）');
} else {
  const dir = await mkdtemp(join(tmpdir(), 'vmprobe-cordis-'));
  const registeredTools = [];
  const approvalReqs = [];
  const applyCalls = { n: 0 };

  /** 复刻 dsh-user-approval：一个以 `approval` 之名提供服务的**兄弟** fiber。 */
  class ApprovalStub extends cordis.Service {
    constructor(ctx) { super(ctx, 'approval'); }
    async request(req) { approvalReqs.push(req); return 'allowed-once'; }
  }
  /** 复刻 dsh-tools：VMProbe 的 `inject: ['tools']` 是必需依赖，得有人提供。 */
  class ToolsStub extends cordis.Service {
    constructor(ctx) { super(ctx, 'tools'); }
    register(def) { registeredTools.push(def); return () => {}; }
  }

  const transport = {
    async state() { return 'connected'; },
    async check() {
      return { probed: true, pubkeyAuth: true, passwordAuth: true, port: 22, serviceKeyInstalled: false };
    },
    async apply() { applyCalls.n += 1; return { exit: 0 }; },
    async heartbeat() { return { ok: true, at: new Date().toISOString(), latencyMs: 1 }; },
  };

  try {
    const app = new cordis.Context();

    // ① 兄弟 entry：服务提供方
    await app.plugin({ name: 'approval-entry', apply: (c) => { c.plugin(ApprovalStub); } }, {});
    await app.plugin({ name: 'tools-entry', apply: (c) => { c.plugin(ToolsStub); } }, {});

    // ② 兄弟 entry：只做两件事 —— 证明"直接读会抛"，并证明"经 get 能拿到"
    let directAccessError = null;
    let viaGet = null;
    await app.plugin({
      name: 'sibling-probe',
      apply(c) {
        try { void c.approval; } catch (err) { directAccessError = err; }
        viaGet = c.get('approval');
      },
    }, {});

    check('★ 真实 cordis 下，兄弟 fiber 里读 `ctx.approval` 确实会抛（与真机报错同源）', () => {
      assert.ok(directAccessError, '本该抛异常，却没有 —— 那说明本节的复刻不成立');
      assert.match(directAccessError.message, /without inject/);
    });
    check('★ 真实 cordis 下，`ctx.get("approval")` 能拿到兄弟提供的那份服务', () => {
      assert.equal(typeof viaGet?.request, 'function', 'get 应能读到兄弟 entry 提供的 approval');
    });

    // ③ 兄弟 entry：VMProbe 自己（inject: ['tools']）
    let loadError = null;
    try {
      await app.plugin(mod, {
        storageDir: dir,
        transport,
        dailyReport: false,
        loadMarkerFile: join(dir, 'loads.jsonl'),
      });
    } catch (err) {
      loadError = err;
    }

    check('★ 真实 cordis 下 VMProbe 能加载（I5 落地时这里会让整棵树起不来）', () => {
      assert.equal(loadError, null, `加载抛错了：${loadError?.message}`);
    });
    check('★ 真实 cordis 下 6 个工具全部注册', () => {
      assert.equal(registeredTools.length, 6, `实际 ${registeredTools.length}`);
    });
    check('真实 cordis 下台账记 approval.available（读到了兄弟 entry 的审批服务）', () => {
      const ledger = readFileSync(join(dir, 'loads.jsonl'), 'utf8');
      assert.ok(ledger.includes('"approval.available"'), `台账：${ledger.trim().split('\n').slice(-3).join(' | ')}`);
    });

    // ④ 执行侧：审批真的经真实服务发起了
    const actionTool = registeredTools.find((d) => d.name === 'vmprobe_action');
    const targetsTool = registeredTools.find((d) => d.name === 'vmprobe_targets');
    const statusTool = registeredTools.find((d) => d.name === 'vmprobe_status');
    const execCtx = { callId: 'c-cordis', signal: new AbortController().signal, arguments: {}, agent: { sessionId: 's-cordis' } };

    await targetsTool.execute(
      { op: 'add', id: 't_cordis', hostname: '10.0.0.11', user: 'ops', authRef: 'VMPROBE_CORDIS_PASSWORD' },
      execCtx,
    );
    const status = await statusTool.execute({}, execCtx);
    check('真实 cordis 下状态工具报告"审批可用"', () => {
      assert.equal(status.approvalAvailable, true);
    });
    const r3 = await actionTool.execute({ target: 't_cordis', action: 'ssh.passwordless.enable' }, execCtx);
    check('★ 真实 cordis 下 R3 的发起的审批确实到达了兄弟 entry 的服务', () => {
      assert.equal(approvalReqs.length, 1, `应发起 1 次审批，实际 ${approvalReqs.length}`);
      assert.equal(r3?.status, 'blocked', `审批后仍应由 echoHostname 护栏阻断，实际 ${r3?.status}`);
      assert.equal(applyCalls.n, 0, '被阻断时一行都不该执行');
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// ===========================================================================
// [12] I7：apply() **永不抛** —— 一条 entry 抛异常 = **整棵插件树加载失败** = DSH 起不来。
//
// 这一节守的不是"某处代码对不对"，而是"**我的 bug 能不能把宿主弄死**"。
// 真机已经因此被咬过两次：(a) `.credentials.yaml` 不是合法 YAML（中文标注 + 全角冒号）；
// (b) 本插件 I5 落地时的 `ctx.approval`。两次的表现完全一样：web.log 里
// `plugin tree failed to load` + `exited with code 1`，浏览器里什么都打不开。
//
// 所以断言的不是"某函数不抛"，而是 **`mod.apply()` 这个对外入口在内部炸掉时也不抛**，
// 且必须留下可追的证据（台账 apply.failed），不能被当成"加载成功"。
// ===========================================================================
console.log('\n[12] I7：apply() 绝不把异常交给 loader（fail-safe）');

{
  const dir = await mkdtemp(join(tmpdir(), 'vmprobe-failsafe-'));
  const ledgerFile = join(dir, 'loads.jsonl');

  /**
   * 造一个**必然失败**的加载条件：storageDir 的父路径是个**文件**。
   * 选它是因为失败点在 `createEngine` 的第一行（`mkdirSync(join(dir,'logs'), {recursive:true})`），
   * 也就是 apply() 的很早期 —— 这正是"闭包/engine 都还不存在"的最坏情况，
   * 台账兜底必须在这种时刻也能写出来。
   */
  const blocker = join(dir, 'blocker');
  writeFileSync(blocker, 'not a directory', 'utf8');
  const brokenStorage = join(blocker, 'sub');

  const newCtx = () => {
    const registered = [];
    const logs = [];
    return {
      registered,
      logs,
      ctx: {
        tools: { register(def) { registered.push(def); return () => {}; } },
        logger: {
          info: (m) => logs.push(['info', m]),
          warn: (m) => logs.push(['warn', m]),
          error: (m) => logs.push(['error', m]),
        },
        get: () => undefined,
        inject: () => {},
      },
    };
  };

  try {
    check('探测点有效：这个 storageDir 确实会让加载失败（否则下面全是空转）', () => {
      assert.throws(() => mkdirSync(join(brokenStorage, 'logs'), { recursive: true }));
    });

    const a = newCtx();
    let applyError = null;
    try {
      mod.apply(a.ctx, {
        storageDir: brokenStorage,
        transport: null,
        dailyReport: false,
        loadMarkerFile: ledgerFile,
      });
    } catch (err) {
      applyError = err;
    }

    check('★ 内部加载失败时 apply() 不抛（真机上这里会让整棵树加载不出来）', () => {
      assert.equal(applyError, null, `apply 抛了：${applyError?.message}`);
    });
    check('★ 失败被记成台账 apply.failed（不是静默变成"加载成功"）', () => {
      const ledger = readFileSync(ledgerFile, 'utf8');
      const line = ledger.split('\n').find((l) => l.includes('"apply.failed"'));
      assert.ok(line, `台账里没有 apply.failed：${ledger.trim().split('\n').slice(-3).join(' | ')}`);
      assert.ok(JSON.parse(line).reason, 'apply.failed 必须带 reason');
    });
    check('★ 台账里**没有** load 事件（不能让"半加载"冒充成功）', () => {
      const ledger = readFileSync(ledgerFile, 'utf8');
      assert.ok(!ledger.includes('"event":"load"'), '失败路径不该出现 load');
    });
    check('失败经 logger.error 说出来（不靠"工具莫名消失"让人猜）', () => {
      const [level, msg] = a.logs.find(([lv]) => lv === 'error') ?? [];
      assert.equal(level, 'error', `实际日志：${JSON.stringify(a.logs)}`);
      assert.match(msg, /加载失败/);
    });
    check('失败时不留半套工具（registered 为空，避免"看起来能用"）', () => {
      assert.equal(a.registered.length, 0, `实际注册 ${a.registered.length} 个`);
    });

    // ---- 开发期开关：strict:true 时照旧抛，别让兜底把 bug 藏起来 ----
    const b = newCtx();
    check('★ `strict: true` 时 apply() 照旧抛（开发/契约检查必须响亮）', () => {
      assert.throws(() => mod.apply(b.ctx, {
        storageDir: brokenStorage,
        transport: null,
        dailyReport: false,
        loadMarkerFile: join(dir, 'loads-strict.jsonl'),
        strict: true,
      }));
    });
    check('strict 抛错的同时也留下了台账（失败原因不丢）', () => {
      const ledger = readFileSync(join(dir, 'loads-strict.jsonl'), 'utf8');
      assert.match(ledger, /apply\.failed/);
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

console.log(`\n${failures === 0 ? '全部通过 ✔' : `失败 ${failures} 项 ✖`}\n`);
process.exit(failures === 0 ? 0 : 1);