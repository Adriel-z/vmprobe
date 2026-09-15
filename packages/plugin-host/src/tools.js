/**
 * 工具定义 —— 模型与 VMProbe 的唯一接口面（DESIGN.md §6.2）。
 *
 * 两条硬约束（均已对着 DSH 的实际类型声明核实）：
 *   1. `ToolDefinition` **必须**声明 `output: { schema, render }`，否则注册无效。
 *   2. 审批请求 `ApprovalRequest` 只有 `agent / toolName / callId / reason / signal`
 *      五个字段，**没有**承载富文本的通道。所以：
 *        · 富 plan（差分、影响面、argv）走 `execute` 返回值 + `presentCall` 渲染；
 *        · 审批只带一句精炼的 `reason`（由 core/risk.js 生成）。
 *
 * M0 只注册**真能工作**的 5 个工具。注册一个永远报错的工具会：
 *   白占每轮请求的 schema token，并诱使模型去调用它。宁可暂不注册。
 */

import { NotImplementedInM0Error } from './engine.js';

/** 连接状态 → 人话。不给"看起来像真状态"的假值（I9）。 */
const CONN_LABEL = {
  'not-wired': '未接线（传输层尚未接入）',
  connected: '已连接',
  detached: '未连接',
  unknown: '未知（传输层未报告状态）',
};

/** DSH 的 ContentBlock：文本块形状已核实。 */
const text = (t) => [{ type: 'text', text: String(t) }];

/**
 * 查询某个凭据引用的配置状态 —— **只拿到"是否已配置"，永远拿不到值**。
 *
 * 这是"密码不进对话"能成立的关键环节：工具必须能告诉用户"还没配凭据、请去 CLI 录入"，
 * 但它自己**看不见**那个值。DSH 的 `describe()` 正是为这种配置界面设计的（不暴露值）。
 */
async function credentialState(ctx, ref) {
  if (!ref) return { configured: false, writable: false, known: false };
  try {
    const svc = ctx?.credentials;
    if (!svc || typeof svc.describe !== 'function') {
      return { configured: false, writable: false, known: false };
    }
    return { ...(await svc.describe(ref)), known: true };
  } catch {
    return { configured: false, writable: false, known: false };
  }
}

/**
 * 把异常重新抛出为**脱敏后**的异常。
 *
 * 为什么必要（推演发现 I8）：工具抛出的错误文本会直接进模型上下文与会话日志，
 * 而它可能来自传输层/远端命令回显 —— 里面可能带凭据或敏感 argv。
 * 这里是最靠近"错误出去"的地方，必须过一道。
 */
function redactError(engine, err) {
  const message = engine?.redactor?.text
    ? engine.redactor.text(err?.message ?? String(err))
    : String(err?.message ?? err);
  const out = new Error(message);
  out.name = err?.name ?? 'Error';
  if (err?.code) out.code = err.code;
  if (err?.verdict) out.verdict = err.verdict;
  return out;
}

/** 包一层：任何异常都先脱敏再抛。 */
async function guarded(engine, fn) {
  try {
    return await fn();
  } catch (err) {
    throw redactError(engine, err);
  }
}

const EMPTY_PARAMS = { type: 'object', properties: {}, additionalProperties: false };

/** 基础用法提示（DESIGN.md §16）。作为 vmprobe_catalog 的返回值，按需拉取，不占常驻 token。 */
export const USAGE_HINT = `## VMProbe 基础用法

### 首次使用（三步）
1. **添加目标**：\`vmprobe_targets { op:"add", id, hostname, user, authRef:"VMPROBE_X_PASSWORD" }\`
   —— \`authRef\` 只填**引用名**，不是密码本身。
2. **录入密码**：让用户执行 \`node tools/vmprobe-cred.mjs set VMPROBE_X_PASSWORD\`（交互式、不回显）。
   ⚠️ **绝不要让用户把密码打在对话里** —— DSH 会话是持久化且会被完整重放的。
   用户若已给过密码文本，应提醒他改用上述命令，并建议轮换该密码。
3. **采集画像**：\`vmprobe_facts { target, refresh:true }\` → 拿到发行版后，动作才能按发行版分流。

### 常用工具
- \`vmprobe_status\`：连接状态 + 目标清单 + 审计链健康度
- \`vmprobe_facts\`：环境画像（发行版/负载/磁盘/待更新）
- \`vmprobe_catalog\`：可用动作清单
- \`vmprobe_action\`：执行动作（plan → 审批 → 执行 → 验证）
- \`vmprobe_logs\`：审计记录

### 常用动作
| 意图 | 动作 | 风险 |
|---|---|---|
| 更新系统 | \`system.update\` | R1（含内核→R2）|
| 配置免密登录 | \`ssh.passwordless.enable\` | R3 |
| 撤销免密登录 | \`ssh.passwordless.disable\` | R3 |
| 采集画像 | \`probe.facts\` | R0 |

### 注意
- 一次只做一个动作；不要假设上一条已生效 —— 用返回的 verify 结果说话
- 动作返回 \`blocked\` 时，把阻塞原因告诉用户，**不要**绕路尝试别的动作
- 参数支持**按发行版区分**：某个参数在当前发行版上没有对应实现时会被 fail-closed 阻断
  （例如 Debian 不支持 \`securityOnly\`），这不是 bug，是刻意的
- 不要自行拼 shell 命令：可用能力以 \`vmprobe_catalog\` 为准`;

/**
 * 构造全部工具定义。
 * @param {object} engine createEngine 的返回值
 * @param {object} ctx DSH 的插件上下文（只用到 approval / jobs / logger）
 * @returns {object[]} ToolDefinition[]
 */
export function createTools(engine, ctx) {
  /**
   * vmprobe_action 的工具级预算（M2-③）。
   *
   * 从**目录里最长**的动作预算推导，而不是拍一个数字：动作自己声明了要跑多久
   * （`system.update` 是 1 小时），工具就不该比它更早掐断；再加 3 分钟余量覆盖
   * 计划、探测、校验与审批往返。
   *
   * 它是**兜底**而非主要防线：连接超时、单命令超时、探测超时都在更内层各自生效，
   * 这里防的是"整体卡死不返回"。
   */
  const ACTION_BUDGET_MS = Math.max(
    600_000,
    ...[...engine.actions.values()].map((a) => (Number.isFinite(a.timeoutMs) ? a.timeoutMs : 0)),
  ) + 180_000;

  const rawTools = [
    // =====================================================================
    // 1. 目录：模型发现能力的入口（同时承载「展示基础用法」需求）
    // =====================================================================
    {
      name: 'vmprobe_catalog',
      description:
        '列出 VMProbe 可执行的受管动作（含参数、风险级、支持的发行版），并返回基础用法提示。' +
        '不确定该用哪个动作时先调用本工具，不要自行拼 shell 命令。',
      parameters: EMPTY_PARAMS,
      output: {
        schema: {
          type: 'object',
          properties: {
            actions: { type: 'array' },
            usage: { type: 'string' },
          },
          required: ['actions', 'usage'],
        },
        render: (_args, value) => {
          const lines = value.actions.map(
            (a) => `- ${a.id} [${a.risk}] ${a.title} —— ${a.summary}（支持：${a.distros.join('/')}）`,
          );
          return text(`${value.usage}\n\n### 当前已加载动作（${value.actions.length}）\n${lines.join('\n')}`);
        },
      },
      presentCall: () => ({ card: 'generic', title: '查看 VMProbe 动作目录', kind: 'read' }),
      isConcurrencySafe: () => true,
      async execute() {
        return { actions: engine.catalogList(), usage: USAGE_HINT };
      },
    },

    // =====================================================================
    // 2. 目标管理
    // =====================================================================
    {
      name: 'vmprobe_targets',
      description:
        '管理受管虚拟机目标：列出 / 新增 / 删除。' +
        '注意：凭据（密码、私钥口令）**不经本工具传递** —— 这里只接受 authRef 引用标识，' +
        '凭据由用户在界面或 CLI 的安全输入中录入。',
      parameters: {
        type: 'object',
        properties: {
          op: { type: 'string', enum: ['list', 'add', 'remove'], description: '操作类型' },
          id: { type: 'string', description: '目标 id（add 时必填，如 t_a1b2）' },
          label: { type: 'string', description: '显示名（如 vm-a）' },
          hostname: { type: 'string', description: '主机名或 IP' },
          port: { type: 'integer', description: 'SSH 端口，默认 22' },
          user: { type: 'string', description: 'SSH 用户名' },
          authRef: { type: 'string', description: '凭据引用（不是凭据本身）' },
          authKind: { type: 'string', enum: ['password', 'key', 'agent'] },
          tags: { type: 'array', items: { type: 'string' }, description: '标签，如 ["prod"]' },
          fingerprint: { type: 'string', description: '主机密钥指纹（SHA256:…）' },
        },
        required: ['op'],
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: { op: { type: 'string' }, targets: { type: 'array' }, target: { type: 'object' } },
          required: ['op'],
        },
        render: (_args, value) => {
          if (value.op === 'list') {
            if (!value.targets.length) return text('当前没有任何受管目标。用 vmprobe_targets op=add 添加。');
            const rows = value.targets.map((t) => {
              const cred = t.credential
                ? (t.credential.configured
                  ? '凭据=已配置'
                  : '凭据=**未配置** → 用 `node tools/vmprobe-cred.mjs set <引用名>` 录入')
                : `认证=${t.authRef.kind}`;
              return `- ${t.label} (${t.id}) → ${t.user}@${t.hostname}:${t.port}`
                + ` · ${cred} · 指纹=${t.hostKey.fingerprint ?? '未固定'} · 标签=[${t.tags.join(',')}]`;
            });
            return text(`受管目标（${value.targets.length}）：\n${rows.join('\n')}`);
          }
          if (value.op === 'remove') return text(`已删除目标 ${value.target?.id ?? ''}`);
          return text(`已添加目标 ${value.target.label} (${value.target.id}) → `
            + `${value.target.user}@${value.target.hostname}:${value.target.port}`
            + (value.hint ? `\n提示：${value.hint}` : ''));
        },
      },
      presentCall: (args) => ({
        card: 'generic',
        title: `目标管理：${args?.op ?? '?'}`,
        kind: args?.op === 'remove' ? 'delete' : args?.op === 'add' ? 'edit' : 'read',
        rawInput: args?.op === 'list' ? undefined : { id: args?.id, hostname: args?.hostname, user: args?.user },
      }),
      async execute(args) {
        const op = args?.op;
        if (op === 'list') {
          const targets = await engine.listTargets();
          // 附上凭据配置状态（**只有"是否已配置"，没有值**）——
          // 没有它，用户只能靠"连不上"来猜是密码没录入还是别的问题。
          const withCred = [];
          for (const t of targets) {
            const credential = t.authRef?.kind === 'password'
              ? await credentialState(ctx, t.authRef?.ref)
              : null;
            withCred.push({ ...t, credential });
          }
          return { op, targets: withCred };
        }
        if (op === 'add') {
          const target = await engine.addTarget({
            id: args.id, label: args.label, hostname: args.hostname, port: args.port ?? 22,
            user: args.user, authRef: args.authRef, authKind: args.authKind, tags: args.tags ?? [],
            fingerprint: args.fingerprint,
          });
          let hint = null;
          if (target.authRef.kind === 'password') {
            const st = await credentialState(ctx, target.authRef.ref);
            if (!st.configured) {
              hint = `凭据 ${target.authRef.ref} 尚未录入。请用 `
                + `\`node tools/vmprobe-cred.mjs set ${target.authRef.ref}\` 交互式录入（不回显），`
                + '不要把密码打在对话里 —— DSH 会话是持久化且会被完整重放的。';
            }
          }
          return { op, target, hint };
        }
        if (op === 'remove') {
          const target = await engine.removeTarget(args.id);
          return { op, target };
        }
        throw new Error(`不支持的操作: ${String(op)}（可选 list / add / remove）`);
      },
    },

    // =====================================================================
    // 3.5 环境画像
    // =====================================================================
    {
      name: 'vmprobe_facts',
      description:
        '获取受管虚拟机的环境画像：发行版/内核/架构/init/包管理器/硬件/负载/SSH 配置。' +
        '默认返回缓存的画像；refresh=true 会重新采集（会连一次 SSH，只读）。',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: '目标 id 或显示名' },
          refresh: { type: 'boolean', description: '是否强制重新采集，默认 false（用缓存）' },
        },
        required: ['target'],
        additionalProperties: false,
      },
      output: {
        // ⚠️ DSH 强制的是 **JSON Schema 子集**（见 dsh-tools/json-schema 模块注释）：
        //    只接受单个标量 type、properties/required/additionalProperties、items、
        //    标量 enum/const、以及**恰好一个分支的 oneOf**。
        //    **不支持 type 数组**（`type: ['string','null']`）—— 那是启动时才发现的错误，
        //    而且一条 entry 失败会让整棵插件树加载不出来。可空字段一律用 oneOf 表达。
        schema: {
          type: 'object',
          properties: {
            targetId: { type: 'string' },
            fresh: { type: 'boolean' },
            savedAt: { oneOf: [{ type: 'string' }, { type: 'null' }] },
            facts: { oneOf: [{ type: 'object' }, { type: 'null' }] },
            hint: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          },
          required: ['targetId', 'fresh', 'facts'],
          additionalProperties: false,
        },
        render: (_args, value) => {
          if (!value.facts) return text(value.hint ?? '没有可用的画像。');
          const f = value.facts;
          const disk = f.hw?.disk?.[0];
          const lines = [
            `${f.os?.prettyName || f.os?.id || '未知发行版'} (${f.os?.id ?? '?'}/${(f.os?.idLike ?? []).join(',') || '-'})`
            + ` · ${f.os?.arch ?? '?'} · 内核 ${f.host?.kernel ?? '?'}`,
            `init=${f.init?.system ?? '?'} · 包管理器=${f.pkg?.default || '(未知)'}`
            + ` · 虚拟化=${f.virt?.type ?? '?'}${f.virt?.container && f.virt.container !== 'none' ? `/${f.virt.container}` : ''}`,
            `负载 ${f.load?.load1 ?? '?'} / ${f.load?.load5 ?? '?'} / ${f.load?.load15 ?? '?'}`,
            `内存 ${f.hw?.mem?.totalMb ?? '?'}MiB（可用 ${f.hw?.mem?.availMb ?? '?'}MiB）`
            + ` · 根分区 ${disk ? `${disk.usedPct}% of ${disk.sizeMb}MiB` : '未知'}`,
            `待更新 ${f.pkg?.upgradable ?? '未知'}（含安全更新 ${f.pkg?.securityUpgradable ?? '未知'}）`
            + ` · 含内核升级=${f.pkg?.kernelUpgradePending ?? '未知'} · 需重启=${f.pkg?.rebootRequired ?? '未知'}`,
            `SSH 端口 ${f.ssh?.port ?? '?'} · 公钥认证=${f.ssh?.pubkeyAuth ?? '未知'} · 密码认证=${f.ssh?.passwordAuth ?? '未知'}`,
            `根权限=${f.caps?.root ?? '?'} · sudo=${f.caps?.sudo ?? '?'} · 可写安装目录=${f.caps?.installDir || '(无)'}`,
          ];
          return text(`[${value.targetId}] ${value.fresh ? '刚采集' : `缓存于 ${value.savedAt ?? '未知'}`}\n${lines.join('\n')}`);
        },
      },
      presentCall: (args) => ({ card: 'generic', title: `采集环境画像 → ${args?.target}`, kind: 'read' }),
      async execute(args) {
        const target = await engine.findTarget(args?.target);
        if (!target) throw new Error(`目标不存在: ${String(args?.target)}`);
        if (args?.refresh) {
          const facts = await engine.collectFacts(target);
          return { targetId: target.id, fresh: true, savedAt: facts.savedAt ?? null, facts };
        }
        const cached = engine.factsFor(target.id);
        if (cached) {
          return { targetId: target.id, fresh: false, savedAt: cached.savedAt ?? null, facts: cached };
        }
        // 没有缓存就直接采集 —— 比让用户"先跑一次别的动作"更符合直觉
        if (!engine.canExecute) {
          return {
            targetId: target.id, fresh: false, savedAt: null, facts: null,
            hint: '尚无画像，且传输层未接线，无法采集。请检查插件配置。',
          };
        }
        const facts = await engine.collectFacts(target);
        return { targetId: target.id, fresh: true, savedAt: facts.savedAt ?? null, facts };
      },
    },

    // =====================================================================
    // 3. 状态
    // =====================================================================
    {
      name: 'vmprobe_status',
      description:
        '查看受管虚拟机的状态：目标清单、连接状态、最近一次画像摘要（发行版/架构/负载/磁盘/待更新）。只读。',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: '目标 id 或显示名；省略则汇总全部' },
        },
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            connectionState: { type: 'string' },
            canExecute: { type: 'boolean' },
            targets: { type: 'array' },
            audit: { type: 'object' },
            warnings: { type: 'array', description: '配置与组合层面的问题（未知键、非法值、审批服务不可用等）' },
            approvalAvailable: { type: 'boolean', description: '审批服务是否可用（不可用时 R2/R3 会被拒绝执行）' },
          },
          required: ['connectionState', 'canExecute', 'targets'],
        },
        render: (_args, value) => {
          const head = `连接状态: ${CONN_LABEL[value.connectionState] ?? value.connectionState}` +
            ` · 可执行动作: ${value.canExecute ? '是' : '否'}`;
          if (!value.targets.length) return text(`${head}\n\n尚无受管目标。`);
          const rows = value.targets.map((t) => {
            // 持续失败时 transport 只会说 no-session（会话已被上一次失败的心跳拆掉），
            // 所以展示时优先用记下来的**最初失败原因**，如实回答"它为什么掉了"。
            const hb = t.lastHeartbeat
              ? (t.lastHeartbeat.ok
                ? `心跳 ${t.lastHeartbeat.latencyMs}ms @ ${t.lastHeartbeat.at.slice(11, 19)}Z`
                : `⚠ 心跳失败（${t.lastHeartbeat.reason}` +
                  `${t.lastHeartbeat.lastFailure && t.lastHeartbeat.lastFailure.reason !== t.lastHeartbeat.reason
                    ? `，最初原因: ${t.lastHeartbeat.lastFailure.reason}` : ''}` +
                  `${t.lastHeartbeat.consecutiveFailures > 1 ? ` ×${t.lastHeartbeat.consecutiveFailures}` : ''}）`)
              : '无心跳（尚无活跃会话）';
            return `- ${t.label}: ${CONN_LABEL[t.connection] ?? t.connection} · ${hb}`
              + `${t.factsSummary ? ` · ${t.factsSummary}` : ''}`;
          });
          const a = value.audit;
          const auditLine = a
            ? `\n审计: ${a.ok ? `链完好（窗口 ${a.length} 条 / 累计 ${a.total} 条` +
                `${a.truncated ? `，已裁剪 ${a.truncated}` : ''}${a.rotations ? `，轮转 ${a.rotations} 次` : ''}）`
              : `⚠ 链损坏 @${a.brokenAt}：${a.reason}`}`
            : '';
          // 配置层面的问题必须**在对话里看得见**（技术债 #1 的第三重可见性：
          // logger + 台账 + 这里）。否则"配了没生效"只能靠翻日志才发现。
          const warn = value.warnings?.length
            ? `\n配置警告（${value.warnings.length}）：\n${value.warnings.map((w) => `  ⚠ ${w}`).join('\n')}`
            : '';
          return text(`${head}\n${rows.join('\n')}${auditLine}${warn}`);
        },
      },
      presentCall: () => ({ card: 'generic', title: '查看虚拟机状态', kind: 'read' }),
      isConcurrencySafe: () => true,
      async execute(args) {
        const all = await engine.listTargets();
        const selected = args?.target
          ? all.filter((t) => t.id === args.target || t.label === args.target)
          : all;
        return {
          connectionState: engine.connectionState,
          canExecute: engine.canExecute,
          targets: selected.map((t) => ({
            id: t.id,
            label: t.label,
            hostname: t.hostname,
            user: t.user,
            authKind: t.authRef.kind,
            fingerprint: t.hostKey.fingerprint,
            tags: t.tags,
            connection: engine.connectionState,
            lastHeartbeat: engine.lastHeartbeat(t.id),
            factsSummary: (() => {
              const f = engine.factsFor(t.id);
              if (!f) return null;
              return `${f.os?.prettyName || f.os?.id || '?'} · 负载 ${f.load?.load1 ?? '?'}`
                + ` · 待更新 ${f.pkg?.upgradable ?? '未知'}`;
            })(),
            lastSeenAt: t.lastSeenAt,
          })),
          audit: engine.verifyAudit(),
          warnings: [
            // I5：审批服务不可用属于"组合/配置"层面的问题，必须与其它配置警告一起出现在对话里 ——
            // 否则用户只会看到"R2/R3 执行不了"，猜不到原因
            ...(ctx?.approval && typeof ctx.approval.request === 'function'
              ? []
              : ['审批服务（ctx.approval）不可用：R0/R1 动作可用，R2/R3 一律拒绝执行（fail-closed）']),
            ...(engine.configWarnings ?? []),
          ],
          approvalAvailable: Boolean(ctx?.approval && typeof ctx.approval.request === 'function'),
        };
      },
    },

    // =====================================================================
    // 4. 动作主入口：plan → approve → apply → verify
    // =====================================================================
    {
      name: 'vmprobe_action',
      description:
        '在受管虚拟机上执行一个受管动作。风险级 R0/R1 直接执行；R2/R3 会先请求用户审批，' +
        '用户拒绝或审批不可用时按 fail-closed 拒绝执行。' +
        '动作与参数见 vmprobe_catalog。',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: '目标 id 或显示名' },
          action: { type: 'string', description: '动作 id（如 system.update）' },
          params: { type: 'object', description: '动作参数，见 vmprobe_catalog' },
        },
        required: ['target', 'action'],
        additionalProperties: false,
      },
      // M2-③：现在**可以**声明 timeoutMs 了 —— 因为取消是真贯通的：
      // 宿主（`dsh-tool-call-timeout-policy`）会把这个额度作为协作式截止时间挂到 `exec.signal` 上，
      // 而我们的 abort 会一路传到 SSH 通道（先给远端发 TERM，3 秒后硬关通道）。
      // **声明它就意味着"与 exec.signal 协作"**，所以这个字段与信号转发必须同时存在。
      //
      // 额度取目录里最长的动作预算（`system.update` 为 1 小时）再加校验余量，是个**兜底**：
      // 真正的逐条保护在更内层（连接/单命令/探测各自有超时），这里只防"整体卡死"。
      timeoutMs: ACTION_BUDGET_MS,
      output: {
        schema: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            plan: { type: 'object' },
            approval: { type: 'object' },
            verify: { type: 'object' },
            run: { type: 'object' },
            result: { type: 'object' },
            error: { type: 'string' },
            hint: { type: 'string' },
          },
          required: ['status', 'plan'],
        },
        render: (_args, value) => {
          const p = value.plan;
          const head = `${p.title?.zh ?? p.actionId} · ${p.targetLabel ?? '?'} · 风险 ${p.risk}` +
            (p.escalatedBy?.length ? `（提权：${p.escalatedBy.join('、')}）` : '');
          const impact = `影响面：${p.impact.summary}`;
          const argv = p.resolvedArgv?.length
            ? `将执行：\n${p.resolvedArgv.map((a) => `  ${a.join(' ')}`).join('\n')}`
            : '将执行：（controller 侧动作，无远端 argv）';
          const state = {
            planned: '已生成计划，等待审批',
            rejected: '用户拒绝，未执行',
            blocked: '已被策略阻断，未执行',
            stale: '计划已失效（过期或环境已变），未执行',
            noop: '已是目标态，无需执行',
            not_implemented: '未实现（M0 骨架）',
            cancelled: '已取消（远端命令已收到 TERM）',
            ok: '执行完成',
          }[value.status] ?? value.status;

          // M2-①：把校验结果如实说出来。"执行成功"与"达到目标态"是两件事。
          const v = value.verify;
          let verifyLine = '';
          if (v) {
            if (v.skipped) {
              verifyLine = `\n校验：未执行（${v.reason ?? '未声明' }）`;
            } else if (v.satisfied === true) {
              verifyLine = `\n校验：✔ 达到目标态（${v.probe}，${v.attempts ?? '?'} 次探测 / ${v.waitedMs ?? '?'}ms）`;
            } else if (v.satisfied === false) {
              verifyLine = `\n校验：★ 未达到目标态（${v.probe}）—— 期望 ${JSON.stringify(v.expect)}，`
                + `实际 ${JSON.stringify(v.state)}`;
            } else {
              verifyLine = `\n校验：未判定（${v.probe}${v.error ? `，探测出错：${v.error}` : '，未声明 expect'}）`;
            }
          }
          const exitLine = value.result && 'exit' in value.result
            ? `\n退出码：${value.result.exit}`
            : '';
          const runLine = value.run?.relPath
            ? `\n运行记录：${value.run.relPath}（${value.run.bytes} 字节，sha256 ${String(value.run.sha256).slice(0, 12)}…）`
            : '';
          const extra = value.error ? `\n错误：${value.error}` : '';
          const hint = value.hint ? `\n提示：${value.hint}` : '';
          return text(`${head}\n${state}\n${impact}\n${argv}${exitLine}${verifyLine}${runLine}${extra}${hint}`);
        },
      },
      presentCall: (args) => ({
        card: 'generic',
        title: `执行动作 ${args?.action ?? '?'} → ${args?.target ?? '?'}`,
        kind: 'execute',
        rawInput: args?.params && Object.keys(args.params).length ? args.params : undefined,
      }),
      presentResult: (args, result) => {
        // 失败时保留原始内容，让错误信息完整可见
        if (result?.isError) return undefined;
        // 结果卡片直接反映**真实结局**（含校验结论）——
        // 这正是"客户端状态徽标"想表达的信息，先在宿主侧如实呈现，
        // 不依赖尚未构建的浏览器侧插件。
        const v = result?.verify;
        const verifyTag = !v ? ''
          : v.skipped ? '（未校验）'
            : v.satisfied === true ? '（✔ 已达目标态）'
              : v.satisfied === false ? '（★ 未达标）'
                : '（校验未判定）';
        const outcome = {
          ok: '完成',
          cancelled: '已取消',
          rejected: '被拒绝',
          blocked: '被阻断',
          stale: '计划失效',
          noop: '无需执行',
          not_implemented: '未实现',
          planned: '待审批',
        }[result?.status] ?? (result?.status ?? '');
        return {
          card: 'generic',
          title: `${args?.action ?? '?'} → ${args?.target ?? '?'}：${outcome}${verifyTag}`,
        };
      },
      async execute(args, exec) {
        const targetRef = args?.target;
        const actionId = args?.action;
        const params = args?.params ?? {};

        // 尽早失败：目标 / 动作不存在时不要走审批
        const target = await engine.findTarget(targetRef);
        if (!target) throw new Error(`目标不存在: ${String(targetRef)}。用 vmprobe_targets op=list 查看。`);
        engine.getAction(actionId);

        // ① 只读计划（M2-③：把 signal 一并带下去，探测也可被取消）
        const plan = await engine.planAction({
          targetId: target.id, actionId, params, signal: exec?.signal ?? null,
        });

        if (plan.blocked) {
          return { status: 'blocked', plan, error: plan.blockedReason };
        }
        if (plan.noop) {
          return { status: 'noop', plan };
        }

        // ② 能力前置检查 —— **必须在申请审批之前**。
        //    对一个做不到的事去征求用户同意，是在浪费用户对审批的注意力。
        //    按 side 区分：controller 侧动作需要本地处理器，agent 侧需要传输层。
        if (!engine.canApply(plan)) {
          const what = plan.side === 'controller'
            ? `controller 侧动作处理器 ${engine.controllerHandlerFor(engine.actions.get(plan.actionId)) ?? '(未声明)'}`
            : '动作实际执行（transport.apply）';
          return {
            status: 'not_implemented',
            plan,
            error: new NotImplementedInM0Error(what, 'M1').message,
            hint: '骨架已打通到「计划 + 审批决策」；对应执行器接线后即可真正执行。',
          };
        }

        // ②.5 TOCTOU 检查（I7）—— **必须在申请审批之前**。
        //     理由与 ② 同源：不要拿一个已经失效的计划去征求用户同意，
        //     用户的注意力是稀缺资源，而且"批准的 12 个包"若已变成"3 个包"，
        //     那已经不是他批准的那件事了。
        const fresh = await engine.verifyPlanFresh(plan, { signal: exec?.signal ?? null });
        if (!fresh.ok) {
          engine.record('action.stale.surfaced', {
            actionId, targetId: target.id, expired: fresh.expired,
            fingerprintChanged: fresh.fingerprintChanged,
          });
          return {
            status: 'stale',
            plan,
            error: fresh.reason,
            hint: '请重新调用本工具重新计划 —— 环境或时间已变化，需要重新确认。不要沿用上一次的批准。',
          };
        }

        // ③ 审批（仅 R2/R3；R0/R1 已由策略判定免弹）
        let approval = { required: false, decision: 'not-required' };
        if (plan.requiresApproval) {
          if (!ctx?.approval || typeof ctx.approval.request !== 'function') {
            return {
              status: 'blocked', plan,
              error: '审批服务不可用，按 fail-closed 拒绝执行。',
            };
          }
          if (!exec?.agent) {
            // 审批请求必须有归属 agent（审计事件要写进它的 session）
            return {
              status: 'blocked', plan,
              error: '本次调用没有归属 agent，无法发起审批；按 fail-closed 拒绝执行。',
            };
          }

          const decision = await ctx.approval.request({
            agent: exec.agent,
            toolName: 'vmprobe_action',
            callId: exec.callId,
            reason: plan.approvalReason,
            signal: exec.signal,
          });
          approval = { required: true, decision, approvalReason: plan.approvalReason };
          engine.record('action.approval', {
            actionId, targetId: target.id, risk: plan.risk, decision,
          });

          if (decision !== 'allowed-once') {
            return { status: 'rejected', plan, approval };
          }
          if (plan.requireEchoHostname) {
            // **fail-closed**：该机制尚未实现时阻断，而不是记一笔"我跳过了"然后继续执行。
            // 推演发现 F3：原来的写法让 R3 的安全护栏在"未实现"状态下静默失效。
            engine.record('action.echoHostname.blocked', {
              actionId, targetId: target.id, risk: plan.risk,
            });
            return {
              status: 'blocked',
              plan,
              approval,
              error:
                `风险级 ${plan.risk} 要求用户复述目标主机名方可确认，` +
                '但该问答机制尚未接线；按 fail-closed 阻断执行。',
              hint: '这是刻意的安全默认：宁可不动，也不在缺少确认环节时执行特权且不可逆的操作。',
            };
          }
        }

        // ④ 执行 + 校验（M2-①：verify 在 applyPlan 内部真正执行）
        try {
          const result = await engine.applyPlan(plan, { signal: exec?.signal ?? null });
          return {
            status: 'ok',
            plan,
            approval,
            verify: result?.verify ?? null,
            run: result?.run ?? null,
            result: result ?? null,
          };
        } catch (err) {
          // 取消是可预期结局：如实说"已取消"并保留运行记录，而不是报成失败
          if (err?.code === 'aborted' || exec?.signal?.aborted) {
            return {
              status: 'cancelled',
              plan,
              approval,
              error: redactError(engine, err),
              hint:
                '已关闭远端通道（取消的实质是关通道；远端是否停下最终取决于服务端）。'
                + '本次执行留有运行记录（runs/），可事后查看已产生的输出；'
                + '若担心远端状态处于中途，请重新采集画像确认，不要直接重试。',
            };
          }
          throw err;
        }
      },
    },

    // =====================================================================
    // 5. 日志与审计
    // =====================================================================
    {
      name: 'vmprobe_logs',
      description:
        '查询 VMProbe 的运行/命令日志与审计链状态（已脱敏，不含任何凭据）。用于回答「上次那个动作结果如何」。',
      parameters: {
        type: 'object',
        properties: {
          limit: { type: 'integer', description: '返回最近多少条，默认 20，上限 200' },
          event: { type: 'string', description: '只看某个事件类型（如 action.plan）' },
        },
        additionalProperties: false,
      },
      output: {
        schema: {
          type: 'object',
          properties: {
            events: { type: 'array' },
            chain: { type: 'object' },
            total: { type: 'integer' },
          },
          required: ['events', 'chain', 'total'],
        },
        render: (_args, value) => {
          const c = value.chain;
          // 链的强度必须说清楚（M5）：无密钥的 sha256 链只能"检出改动"，
          // 不能挡"重算整条链"的伪造 —— 这句话不能只写在文档里，得出现在每次查看时。
          const strength = c.keyed
            ? (c.forgeryResistant
              ? ` · 密钥保护（keyId ${c.keyId}，抗伪造）`
              : ` · 密钥保护中（keyId ${c.keyId}；另有 ${c.legacyCount} 条旧的无密钥记录，那段只可检出改动）`)
            : ' · ⚠ 无密钥：可检出改动，但挡不住"重算整条链"的伪造';
          const head = c.ok
            ? `审计链完好（共 ${value.total} 条${c.truncated ? `，内存窗口已裁剪 ${c.truncated} 条` : ''}）${strength}`
            : `⚠ 审计链已损坏：第 ${c.brokenAt} 条起断链（${c.reason}）`;
          if (!value.events.length) return text(`${head}\n\n暂无匹配记录。`);
          const rows = value.events.map((e) => {
            const brief = Object.entries(e)
              .filter(([k]) => !['ts', 'prev', 'hash', 'event', 'algo', 'keyId'].includes(k))
              .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
              .join(' ');
            return `${e.ts}  ${e.event}  ${brief}`;
          });
          return text(`${head}\n\n${rows.join('\n')}`);
        },
      },
      presentCall: () => ({ card: 'generic', title: '查询 VMProbe 日志', kind: 'read' }),
      isConcurrencySafe: () => true,
      async execute(args) {
        const limit = Math.min(Math.max(Number(args?.limit) || 20, 1), 200);
        const all = engine.audit.snapshot();
        const filtered = args?.event ? all.filter((e) => e.event === args.event) : all;
        return {
          events: filtered.slice(-limit),
          chain: engine.verifyAudit(),
          total: all.length,
        };
      },
    },
  ];

  // 统一出口：所有工具的错误都先脱敏再抛出。
  // 放在这一处而不是每个工具里，是为了不可能"漏掉某个工具"（I8）。
  return rawTools.map((def) => ({
    ...def,
    async execute(args, exec) {
      return guarded(engine, () => def.execute(args, exec));
    },
  }));
}
