/**
 * VMProbe DSH Host 插件入口。
 *
 * 约定（已对着 DSH 的 dsh-tool-todo 文档核实）：
 *   · 函数插件导出 `name` / `inject` / `apply`；
 *   · **不得有 `default` 导出** —— Loader 的 unwrapExports 会折叠模块并丢掉 `inject`。
 *
 * `apply` 是**同步**的：CORDIS 是否 await 异步 apply 未经核实，因此不依赖它。
 * 目录加载与存储目录创建都用同步 API（文件极小），工具执行仍全部异步。
 */

import { appendFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createEngine } from './engine.js';
import { createTools, USAGE_HINT } from './tools.js';
import { approvalAvailable, optionalService, resolveCredentials } from './services.js';
import { startDailyReportScheduler, startTransportHeartbeat } from './scheduler.js';
import { createSshTransport } from '../../transport/src/ssh.js';
import { enablePasswordless, disablePasswordless } from '../../transport/src/passwordless.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * 协从端引导脚本的位置。
 *
 * 它是**经 SSH stdin 投递**给远端执行的（`sh -s -- --check`），所以不需要远端预装任何东西 ——
 * 只要有一个 POSIX sh。这也是"零安装首次接触"能成立的原因。
 * 用 `file:` 协议安装（拷贝而非符号链接）时这个文件可能不在，此时 facts 采集不可用，
 * 但 exec/apply 仍然能工作，所以这里只告警、不阻断插件加载。
 */
export const DEFAULT_AGENT_SCRIPT = join(HERE, '..', '..', '..', 'agent', 'bootstrap.sh');

/** 插件名（与 cordis.patch.yml 里的 id 无关，这是模块级标识）。 */
export const name = 'vmprobe';

/**
 * 静态注入。缺失即"插件不运行"（cordis 语义：`inject` 里的服务必须先就绪）。
 *
 * ── I5 决策（第七轮）：`approval` **刻意不再是必需注入** ────────────────────
 *
 * 原来写的是 `inject = ['tools', 'approval']`，理由是"没有审批器就无法安全执行 R2/R3"。
 * 理由没错，但**手段错了**：`inject` 里的服务未就绪时，本插件的 `apply()` 根本不会执行 ——
 * 表现为工具一个都没注册，甚至那条 loader entry 加载失败（而**任何一条 entry 失败都会让整棵树
 * 加载不出来**，见 `DEVELOPMENT.md` §5.2 坑 6）。一个可选服务的缺失不该有这个权力。
 *
 * 改为：**加载时永不阻塞，执行时严格 fail-closed**。
 *   · `tools` 仍是必需（没有它插件什么也做不了，失败是应该的）；
 *   · `approval` 缺失时插件照常加载并注册工具，但：
 *       - R0/R1（免弹动作）照常执行 —— 它们本来就不需要审批；
 *       - R2/R3 一律拒绝执行，并明确说明"审批服务不可用，按 fail-closed 拒绝"；
 *       - 加载台账与 `vmprobe_status` 都会显示"审批服务不可用"，**不静默**。
 * 安全属性没有变弱（没有审批就绝不执行特权且不可逆的动作），但消除了"缺服务即整棵树失败"的隐患。
 *
 * ⚠️ **I6 补丁（第九轮真机验证）**：I5 只改了"要不要 inject"，漏了"怎么读"。
 * cordis 读一个未注入的服务名会**抛异常**（不是返回 undefined），于是 apply() 里那句
 * `ctx.approval &&` 本身就把整棵树带崩了（`cannot get property "approval" without inject`）。
 * 现在所有可选服务一律经 `services.js` 的 `optionalService()` 读取 —— 理由与实测见该文件。
 *
 * ⚠️ 同理刻意**不注入 `timer`**：定时日报是可选特性，缺依赖时只告警不阻塞。
 */
export const inject = ['tools'];

/** 默认存储目录：尊重 DSH_HOME，与 DSH 自身的数据布局保持一致（推演发现 F11）。 */
export const DEFAULT_STORAGE_DIR = join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'vmprobe');

/**
 * 插件入口。
 * @param {object} ctx CORDIS 上下文
 * @param {object} [config] cordis.patch.yml 里的 config
 */
export function apply(ctx, config = {}) {
  const storageDir = config.storageDir ?? DEFAULT_STORAGE_DIR;

  // ---- 凭据访问：**按操作现取**，且延迟到调用时才碰服务 ----
  //
  // 两个理由：
  //   ① DSH 的凭据服务语义就是"每次操作重新解析"，这类改动无需重启插件即可生效；
  //   ② `apply()` 可能跑在 credentials 服务就绪**之前**（与定时器同一个容器顺序问题），
  //      所以不能在 apply 时就把服务实例抓下来 —— 必须在调用时读。
  //
  // ⚠️ 读法必须是 `resolveCredentials(ctx)`（= `ctx.get('credentials')`）而不是 `ctx.credentials`：
  //    后者在"服务存在但本 fiber 未注入"时会**抛异常**（I6，见 services.js）。
  const credentials = {
    async resolve(ref) {
      const svc = resolveCredentials(ctx);
      if (!svc || !ref) return undefined;
      const resolved = await svc.resolve(ref);
      return resolved?.value;
    },
    async describe(ref) {
      const svc = resolveCredentials(ctx);
      if (!svc || !ref) return { configured: false, writable: false };
      return svc.describe(ref);
    },
  };

  // ---- 传输层（SSH）----
  //
  // 没有它，agent 侧动作只能推进到「计划 + 审批」，不能执行（fail-closed）。
  //
  // 配置里**显式给了 `transport`** 就照用（`transport: null` 表示刻意不接线 ——
  // 契约测试与离线环境用得上）；没给才自动创建 SSH 传输层。
  let transport = null;
  if ('transport' in config) {
    transport = config.transport ?? null;
  } else {
    try {
      const scriptPath = config.agentScriptPath ?? DEFAULT_AGENT_SCRIPT;
      if (!existsSync(scriptPath)) {
        // 用 `file:` 协议安装（拷贝）时脚本可能不在 —— 只告警，exec/apply 仍然可用
        ctx.logger?.warn?.(`vmprobe: 找不到协从端脚本 ${scriptPath}，facts 采集将不可用（exec/apply 不受影响）`);
      }
      transport = createSshTransport({
        resolveTarget: async (targetId) => {
          const targets = await engine.listTargets();
          return targets.find((t) => t.id === targetId) ?? null;
        },
        resolveCredential: (ref) => credentials.resolve(ref),
        keyDir: join(storageDir, 'keys'),
        agentScriptPath: scriptPath,
        hostKeyPolicy: config.hostKeyPolicy ?? 'accept-new',
        connectTimeoutMs: config.connectTimeoutMs,
        commandTimeoutMs: config.commandTimeoutMs,
        logger: ctx.logger,
        onHostKey: async (targetId, fingerprint) => {
          // 首连固定指纹（TOFU）。属 R1（可逆变更）→ 免弹但必须留痕；变更不静默覆盖。
          await engine.pinHostKey(targetId, fingerprint);
        },
      });
    } catch (err) {
      ctx.logger?.warn?.(`vmprobe: 传输层未启用 —— ${err?.message ?? err}`);
    }
  }

  const engine = createEngine({
    dir: storageDir,
    catalogDir: config.catalogDir,
    transport,
    config,
    controllerHandlers: new Map([
      // 采集画像：控制器经 SSH stdin 投递引导脚本执行，**不要求远端预装任何东西**
      ['probe.facts', async (plan) => {
        const target = await engine.findTarget(plan.targetId);
        if (!target) throw new Error(`目标不存在：${plan.targetId}`);
        const facts = await engine.collectFacts(target);
        return { facts };
      }],
      // 免密登录事务：整个项目风险最高的一段，见 packages/transport/src/passwordless.js
      ['auth.enablePasswordless', async (plan) => {
        const target = await engine.findTarget(plan.targetId);
        if (!target) throw new Error(`目标不存在：${plan.targetId}`);
        if (target.authRef?.kind === 'key') {
          return { ok: true, already: true, note: '该目标已在用密钥认证，无需切换' };
        }
        const report = await enablePasswordless(transport, target, {
          onStep: (step, detail) => engine.record('auth.passwordless.step', {
            targetId: target.id, step, detail,
          }),
        });
        // 事务成功后才切换 authRef 并固定指纹 —— 顺序不能反
        await engine.switchTargetAuth(target.id, report.authRefAfter);
        engine.record('auth.passwordless.done', {
          targetId: target.id,
          keyId: report.keyId,
          publicKeyLine: report.publicKeyLine,
          authorizedKeysPath: report.authorizedKeysPath,
          createdKey: report.createdKey,
        });
        return report;
      }],
      // 撤销免密：与启用对称的事务 —— 删 key 之前必须先用密码验证"还有路可走"
      ['auth.passwordless.disable', async (plan) => {
        const target = await engine.findTarget(plan.targetId);
        if (!target) throw new Error(`目标不存在：${plan.targetId}`);
        if (target.authRef?.kind !== 'key') {
          return { ok: true, already: true, note: '该目标当前不是密钥认证，无需撤销' };
        }
        const report = await disablePasswordless(transport, target, {
          passwordRef: plan.params?.passwordRef ?? null,
          onStep: (step, detail) => engine.record('auth.passwordless.disable.step', {
            targetId: target.id, step, detail,
          }),
        });
        await engine.switchTargetAuth(target.id, report.authRefAfter);
        engine.record('auth.passwordless.disabled', {
          targetId: target.id, marker: report.marker, authorizedKeysPath: report.authorizedKeysPath,
        });
        return report;
      }],
    ]),
  });

  // ---- 加载台账（默认开启，可关）----
  //
  // 为什么需要它：`ctx.logger` 的输出不一定进 stdout，也不一定进 DSH 的日志文件
  // （实测用 `--patch` 启一个实例时，用户日志目录完全没被写入；而 `--help` 更是在
  // 加载插件树之前就短路了）。于是"插件到底有没有被加载"这个最基本的问题，
  // 靠看日志是**答不上来**的 —— 而这恰恰是本地插件挂载最容易出错的地方。
  //
  // 台账是**事件流**而非单行：定时器要等依赖就绪后才启动，那一刻的事实只有单独记一行
  // 才看得见 —— 否则"加载时 scheduler 还没起来"会被误读成"定时器没工作"。
  const markerTarget = config.loadMarkerFile === false
    ? null
    : (typeof config.loadMarkerFile === 'string'
      ? config.loadMarkerFile
      : join(engine.dir, 'loads.jsonl'));

  const ledger = (event, fields = {}) => {
    if (!markerTarget) return;
    try {
      appendFileSync(markerTarget, `${JSON.stringify({
        ts: new Date().toISOString(), pid: process.pid, plugin: name, event, ...fields,
      })}\n`, 'utf8');
    } catch (err) {
      ctx.logger?.warn?.(`vmprobe: 写加载台账失败 —— ${err?.message ?? err}`);
    }
  };

  // ---- 配置层面的问题：**必须说出来**（技术债 #1）----
  //
  // 抽掉死键之后，"配置写了但不生效"这类事必须变成可见的：
  // 未知键、非法值、以及比默认更宽松的审批阈值，全部经 logger + 台账 + 状态工具三重可见。
  for (const warning of engine.configWarnings) {
    ctx.logger?.warn?.(`vmprobe: ${warning}`);
    ledger('config.warning', { warning });
  }
  // 生效策略也记一条台账：口径与审计里的 config.effective 一致，便于对着看
  ledger('config.effective', {
    autoAllowUpTo: engine.policy.autoAllowUpTo,
    planTtlMs: engine.config.planTtlMs,
    maxRunBytes: engine.config.maxRunBytes,
    warningCount: engine.configWarnings.length,
  });

  // ---- 审批服务可用性（I5）：**必须显式可见**，不能靠"R2/R3 莫名被拒"才发现 ----
  //
  // 决策见文件头：approval 是可选注入，缺失时插件照常加载，但 R2/R3 会被 fail-closed 拒绝。
  // 既然选择了"不阻塞加载"，就有义务把"审批不可用"这件事说清楚 ——
  // 否则用户只会看到"特权动作执行不了"，猜不到原因。
  //
  // ⚠️ 读取必须走 `approvalAvailable(ctx)`（内部用 `ctx.get`）。写成 `ctx.approval` 会抛异常，
  //    而**抛在这个位置等于整棵插件树加载失败** —— I5 落地时就是这么把 DSH 弄成起不来的。
  if (!approvalAvailable(ctx)) {
    ctx.logger?.warn?.(
      'vmprobe: 审批服务（ctx.approval）不可用 —— 插件已加载，R0/R1 只读与可逆动作可用，'
      + 'R2/R3 特权动作将按 fail-closed 一律拒绝执行，直到审批服务就绪。',
    );
    ledger('approval.unavailable', { note: 'R2/R3 将被拒绝执行（fail-closed）' });
  } else {
    ledger('approval.available');
  }

  // ---- 注册工具 ----
  const tools = createTools(engine, ctx);
  const disposers = tools.map((def) => {
    const dispose = ctx.tools.register(def);
    return typeof dispose === 'function' ? dispose : () => {};
  });

  // ---- 基础用法提示（极简，进每轮请求前缀，必须克制）----
  // 完整用法走 vmprobe_catalog 按需拉取，避免常驻 token 开销。
  //
  // 同 I6：`ctx.systemPrompt` 也是一个"未注入即抛"的服务，所以经 optionalService 读。
  //
  // 签名已核实（不再猜）：`PromptSection = { name, order, text }`
  //   —— dsh-system-prompt/lib/types/index.d.ts:47，且 `section()` 对非有限 `order` 直接
  //      抛 TypeError（lib/index.js:186）。此前写的 `{ id, title, content }` 三个字段**全错**，
  //      抛出的 TypeError 又被本段 try/catch 吞成一条"不可用"告警 —— 于是提示从未注入，
  //      而日志看起来只像"宿主不支持"。这是同一类错误的第 N 次重演：**签名不核实 = 静默失效**。
  //   —— order 约定：100–199 给工具指引（同文件 51-55 行的注释）。
  try {
    const systemPrompt = optionalService(ctx, 'systemPrompt');
    if (systemPrompt && typeof systemPrompt.section === 'function') {
      systemPrompt.section({
        name: 'vmprobe',
        order: 150,
        text:
          '本会话装配了 VMProbe，可经 SSH 管理 Linux 虚拟机。' +
          '执行任何变更前先用 vmprobe_catalog 确认可用动作；不要自行拼 shell 命令。' +
          '风险级由动作目录决定，R2/R3 会自动请求用户审批 —— 用户拒绝时如实转述，不要换动作绕过。',
      });
    } else {
      // 不静默失败：服务不可用时留下明确告警而不是假装成功
      ctx.logger?.warn?.(
        'vmprobe: ctx.systemPrompt.section 不可用，基础用法提示未注入（完整用法仍可经 vmprobe_catalog 获取）',
      );
    }
  } catch (err) {
    ctx.logger?.warn?.(`vmprobe: 注入 systemPrompt 失败（不影响工具可用性）：${err?.message ?? err}`);
  }

  // ---- 每日报告定时器：用**可选注入**等 timer 就绪 ----
  //
  // ⚠️ 这是实测抓出来的真问题（原实现直接调 ctx.interval）：
  //    `inject` 的语义是"这些服务必须在插件运行前就绪"。定时器服务不在我的 inject 里，
  //    于是 apply() 可能在它就绪**之前**就跑了 → `ctx.interval` 还不存在 →
  //    定时器压根没注册，而且**没有任何报错**（生产环境的表现就是"日报永远不出现"）。
  //
  //    不能简单把 'timer' 加进 inject：那会让"没有 timer 的 profile"里整个插件加载失败 ——
  //    而定时日报只是可选特性，不该有这个权力。
  //    `ctx.inject([...], cb)` 正是为这种情况准备的：依赖就绪时执行回调，
  //    缺失则永不执行，且**不阻塞插件加载**。
  let scheduler = null;
  let heartbeat = null;

  if (config.dailyReport === false) {
    ledger('scheduler.disabled', { reason: 'config.dailyReport=false' });
  } else if (typeof ctx.inject === 'function') {
    ctx.inject(['timer'], (timerCtx) => {
      // ① 连接心跳：把"SSH 始终连接"这个承诺变成可观测的事实
      try {
        heartbeat = startTransportHeartbeat({ engine, ctx: timerCtx, config });
        if (heartbeat.scheduled) {
          ledger('heartbeat.started', { intervalMs: heartbeat.intervalMs });
        } else {
          ledger('heartbeat.not-started', { reason: 'ctx.interval unavailable' });
        }
      } catch (err) {
        timerCtx.logger?.warn?.(`vmprobe: 连接心跳未启动 —— ${err?.message ?? err}`);
        ledger('heartbeat.failed', { reason: err?.message ?? String(err) });
      }

      // ② 每日报告
      try {
        scheduler = startDailyReportScheduler({ engine, ctx: timerCtx, config });
        if (scheduler.scheduled) {
          timerCtx.logger?.info?.(
            `vmprobe: 每日报告已排程（UTC ${scheduler.atUtc}，每 ${scheduler.tickMs / 1000}s 检查一次，`
            + '幂等：当天已生成则跳过）',
          );
          ledger('scheduler.started', { atUtc: scheduler.atUtc, tickMs: scheduler.tickMs });
        } else {
          ledger('scheduler.not-started', { reason: 'ctx.interval unavailable in injected ctx' });
        }
      } catch (err) {
        // 配置非法（例如 reportAtUtc 格式错）不应让整个插件失败，但要说得清楚
        timerCtx.logger?.warn?.(`vmprobe: 每日报告未启用 —— ${err?.message ?? err}`);
        ledger('scheduler.failed', { reason: err?.message ?? String(err) });
      }
    });
  } else {
    ctx.logger?.warn?.('vmprobe: ctx.inject 不可用，每日报告与心跳定时器无法启动');
    ledger('scheduler.failed', { reason: 'ctx.inject unavailable' });
  }

  ctx.logger?.info?.(
    `vmprobe: 已注册 ${tools.length} 个工具（${tools.map((t) => t.name).join(', ')}）；` +
    `存储目录 ${engine.dir}；动作 ${engine.actions.size} 个；传输层 ${engine.canExecute ? '已接线' : '未接线（M0）'}`,
  );

  // 台账最后再记一条 "load"：它标志 apply() 走到了末尾（前面任何一步抛错都不会有这行）
  ledger('load', {
    tools: tools.map((t) => t.name),
    storageDir: engine.dir,
    actions: engine.actions.size,
    transport: engine.connectionState,
  });

  // ---- 释放 ----
  if (typeof ctx.on === 'function') {
    ctx.on('dispose', () => {
      try {
        scheduler?.stop();
      } catch {
        /* 定时器释放失败不影响其它资源 */
      }
      try {
        heartbeat?.stop();
      } catch {
        /* 同上 */
      }
      for (const dispose of disposers) {
        try {
          dispose();
        } catch {
          /* 释放失败不影响其它工具 */
        }
      }
    });
  }

  // 注意：**不返回 engine**。CORDIS 会把 apply 的返回值当作 disposer 处理，
  // 返回对象有被误判的风险。需要 engine 时经 ctx 服务或调试钩子暴露（M1 处理）。
}

/** 供外部（文档/测试/CLI）引用的用法提示常量。 */
export { USAGE_HINT };
