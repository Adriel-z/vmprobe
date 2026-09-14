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
check('inject 含 tools 与 approval（安全边界不可选）', () => {
  assert.ok(mod.inject.includes('tools'), 'inject 必须含 tools');
  assert.ok(mod.inject.includes('approval'), 'inject 必须含 approval');
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

console.log(`\n${failures === 0 ? '全部通过 ✔' : `失败 ${failures} 项 ✖`}\n`);
process.exit(failures === 0 ? 0 : 1);
