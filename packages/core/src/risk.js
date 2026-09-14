/**
 * 风险分级与审批策略 —— VMProbe 的安全核心。
 *
 * 设计依据（DESIGN.md §3 D5 / §6.3）：
 *   - 风险级由「动作目录 + 运行时判定」决定，**模型不可指定**。这是防止模型自我降级权限的关键不变式。
 *   - 用户已拍板：R0/R1 免弹但全量留痕；R2/R3 每次审批；R3 额外要求复述主机名。
 *   - DSH 的审批请求（ApprovalRequest）只有 `reason` 一个自由文本通道，
 *     因此本模块产出的 `approvalReason` 是给用户看的**唯一**人性化说明，必须精炼且含影响面。
 */

/** 风险级（闭集）。 */
export const Risk = Object.freeze({
  /** 只读、无副作用：探针、状态、日志读取。 */
  R0: 'R0',
  /** 可逆变更：装包、改配置、写文件、启停服务。 */
  R1: 'R1',
  /** 破坏性或影响面大：含内核升级、需重启、批量变更。 */
  R2: 'R2',
  /** 特权且不可逆：重启、删数据、改 sshd 配置、切换认证方式。 */
  R3: 'R3',
});

const ORDER = ['R0', 'R1', 'R2', 'R3'];

/** 取两者中更高的风险级（只升不降）。 */
export function maxRisk(a, b) {
  const ia = ORDER.indexOf(a);
  const ib = ORDER.indexOf(b);
  if (ia < 0) throw new Error(`unknown risk: ${a}`);
  if (ib < 0) throw new Error(`unknown risk: ${b}`);
  return ia >= ib ? a : b;
}

/** 默认策略。用户决策：autoAllowUpTo = R1。 */
export const DEFAULT_POLICY = Object.freeze({
  /** 该级及以下免弹窗（但仍写审计）。 */
  autoAllowUpTo: Risk.R1,
  /** 带 prod 标签的目标把低于此级的行为提升到该级。 */
  prodEscalatesTo: Risk.R2,
  /** 该级及以上必须审批。 */
  alwaysAskFrom: Risk.R2,
  /** 该级及以上要求用户复述目标主机名方可确认。 */
  echoHostnameAt: Risk.R3,
  /** 只读操作是否也写命令日志。 */
  auditReadOnly: true,
});

/**
 * 判断某次动作是否需要审批，以及审批文案。
 *
 * @param {object} input
 * @param {string} input.risk 动作目录给出的基线风险级。
 * @param {{hostname?: string, label?: string, tags?: string[]}} [input.target]
 * @param {typeof DEFAULT_POLICY} [input.policy]
 * @param {'ask'|'never'} [input.approvalPolicy] 会话的有效审批策略（来自 DSH）。
 * @param {{ kernelUpgradePending?: boolean, rebootRequired?: boolean }} [input.escalate]
 *        运行时提权依据（来自 plan 阶段的只读探测）。
 * @returns {{
 *   baseRisk: string, effectiveRisk: string, escalatedBy: string[],
 *   requiresApproval: boolean, requireEchoHostname: boolean,
 *   audit: boolean, blocked: boolean, blockedReason?: string,
 *   approvalReason: string
 * }}
 */
export function decideApproval(input) {
  const {
    risk,
    target = {},
    policy = DEFAULT_POLICY,
    approvalPolicy = 'ask',
    escalate = {},
  } = input;

  if (!ORDER.includes(risk)) throw new Error(`unknown risk: ${risk}`);

  let effectiveRisk = risk;
  const escalatedBy = [];

  // 生产标签：只升不降
  if (Array.isArray(target.tags) && target.tags.includes('prod')) {
    const bumped = maxRisk(effectiveRisk, policy.prodEscalatesTo);
    if (bumped !== effectiveRisk) {
      escalatedBy.push(`target:prod→${bumped}`);
      effectiveRisk = bumped;
    }
  }

  // 运行时提权：含内核升级或需重启，绝不能停在 R1
  if (escalate.kernelUpgradePending && ORDER.indexOf(effectiveRisk) < ORDER.indexOf(Risk.R2)) {
    effectiveRisk = Risk.R2;
    escalatedBy.push('kernelUpgradePending→R2');
  }
  if (escalate.rebootRequired && ORDER.indexOf(effectiveRisk) < ORDER.indexOf(Risk.R2)) {
    effectiveRisk = Risk.R2;
    escalatedBy.push('rebootRequired→R2');
  }

  const idx = ORDER.indexOf(effectiveRisk);
  /**
   * 免弹阈值 `autoAllowUpTo` 与强制审批阈值 `alwaysAskFrom` **两者都要生效**：
   *   · 高于 autoAllowUpTo ⇒ 必须审批（这是"分级放行"的语义）；
   *   · 达到 alwaysAskFrom ⇒ 必须审批（这是"无论怎么放宽都至少从这级起要问"的下限）。
   *
   * ⚠️ 技术债 #1 的一部分：这里原来**只**看 alwaysAskFrom，
   *    于是 `autoAllowUpTo` 在文档里写着"该级及以下免弹窗"、代码里却完全没参与判定 ——
   *    一个**看起来生效、实际无效**的策略键（正是本项目最想消灭的那一类）。
   *    默认值（R1 / R2）下两种写法的结果完全一致，因此这是纯粹的"让文档成真"，
   *    不改变既有默认行为。
   */
  const requiresApproval = idx > ORDER.indexOf(policy.autoAllowUpTo)
    || idx >= ORDER.indexOf(policy.alwaysAskFrom);
  const requireEchoHostname = idx >= ORDER.indexOf(policy.echoHostnameAt);
  const audit = policy.auditReadOnly || idx > ORDER.indexOf(Risk.R0);

  // fail-closed：策略为 never 而本动作又必须审批 → 直接阻断，而不是放行
  if (requiresApproval && approvalPolicy === 'never') {
    return {
      baseRisk: risk,
      effectiveRisk,
      escalatedBy,
      requiresApproval,
      requireEchoHostname,
      audit,
      blocked: true,
      blockedReason:
        `当前会话审批策略为 never，而该动作风险级为 ${effectiveRisk}（需人工确认）。` +
        '已按 fail-closed 拒绝执行。请切换到允许审批的会话或降低动作风险。',
      approvalReason: '',
    };
  }

  return {
    baseRisk: risk,
    effectiveRisk,
    escalatedBy,
    requiresApproval,
    requireEchoHostname,
    audit,
    blocked: false,
    // 不变式：免弹的动作不产生审批文案。
    // 留一个现成的 reason 字符串会诱使调用方在无需审批时也去发起审批请求。
    approvalReason: requiresApproval
      ? buildApprovalReason({ effectiveRisk, target, escalatedBy })
      : '',
  };
}

/**
 * 生成审批请求的 `reason` 字段。
 *
 * 这是 ApprovalRequest 里唯一的自由文本通道（其余只有 agent/toolName/callId），
 * 所以它必须一句话说清「谁、什么、影响面」。差分明细走工具结果的富渲染。
 */
export function buildApprovalReason({ effectiveRisk, target, escalatedBy = [] }) {
  const who = target.label
    ? `${target.label}${target.hostname && target.hostname !== target.label ? ` (${target.hostname})` : ''}`
    : (target.hostname ?? '目标虚拟机');
  const level = {
    R1: '可逆变更',
    R2: '影响面较大',
    R3: '特权且不可逆',
  }[effectiveRisk] ?? effectiveRisk;
  const esc = escalatedBy.length ? `；提权依据：${escalatedBy.join('、')}` : '';
  const tail = effectiveRisk === Risk.R3
    ? '。确认前将要求你复述目标主机名。'
    : '。';
  return `在 ${who} 上执行一个${level}的动作（风险级 ${effectiveRisk}）${esc}${tail}`;
}
