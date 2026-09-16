/**
 * 可选服务的**唯一**读取入口（I6 决策）。
 *
 * ── 为什么需要这个文件 ───────────────────────────────────────────────────────
 *
 * cordis 的上下文是 **Proxy**：访问一个"已声明、但当前 fiber 没有注入"的服务名时，
 * 它**抛异常**，而不是返回 `undefined`：
 *
 *     Error: cannot get property "approval" without inject
 *
 * 这在 cordis 里是自洽的（`inject` 声明的是"依赖"），但它与 JS 里最常见的那种
 * 可选依赖写法（`ctx.optional?.foo()`）**语义正好相反** —— 惯用写法在这里变成**硬失败**。
 * 而 apply() / 工具执行里任何未捕获的异常都是致命的：
 *   · apply() 抛 → 那条 loader entry 失败 → **整棵插件树加载不出来**（实测，见 DEVELOPMENT §5.2 坑 18）
 *   · execute() 抛 → 用户看到一句语焉不详的报错，而不是"审批服务不可用"
 *
 * DSH 自己的做法是 `ctx.get(name)`：`dsh-tools` 的 `serviceAsk`、`dsh-tool-bash`、
 * `dsh-tool-fs`、`dsh-tool-pwsh`、`dsh-subagent`、`dsh-host-apiproxy` 全都这么写。
 * cordis 对它的定义是 "Read a service from the store **without the inject requirement**"，
 * 未提供时返回 `undefined` —— 正是"可选依赖"该有的语义。
 *
 * ⚠️ 仍然**不**把 approval 写回 `inject`：`inject` 里的服务缺失会让 apply() 根本不执行
 * （I5 决策，见 index.js 文件头）。"加载期不阻塞 + 执行期 fail-closed"的口径不变，
 * 本文件只是把 I5 漏掉的那一步（**读**的口径）补齐。
 */

/**
 * 读一个**可选**服务。
 *
 * 不可用（未组合 / 未就绪 / 本 fiber 未注入）时返回 `undefined`，**永不抛异常**。
 *
 * @param {object} ctx cordis 上下文（或测试/契约检查里的裸对象）
 * @param {string} name 服务名
 * @returns {any|undefined}
 */
export function optionalService(ctx, name) {
  if (!ctx || !name) return undefined;

  // 首选：DSH/cordis 的正式入口 —— 无注入要求，缺失即 undefined
  try {
    if (typeof ctx.get === 'function') {
      const found = ctx.get(name);
      if (found !== undefined) return found;
    }
  } catch {
    // reflect.get 理论上不抛；万一抛了也只能当作"不可用" —— 绝不把异常往上带
  }

  // 兜底：契约检查与单元测试用的是裸对象 ctx（服务直接挂在字段上）。
  // 真实 cordis 上下文走到这里会抛 "cannot get property … without inject"，
  // 吞掉即可 —— 结论与"未注入 = 不可用"完全一致。
  try {
    return ctx[name];
  } catch {
    return undefined;
  }
}

/** 审批服务（R2/R3 的决策入口）。 */
export function resolveApproval(ctx) {
  return optionalService(ctx, 'approval');
}

/**
 * 审批服务是否**可用**（存在且实现了 request）。
 *
 * 口径说明：这里回答的是"现在能不能发起审批"，而不是"审批插件有没有被组合进来"——
 * 调用方拿它决定 R2/R3 能不能执行，所以"服务在、但没有 request 方法"同样算不可用。
 */
export function approvalAvailable(ctx) {
  const svc = resolveApproval(ctx);
  return Boolean(svc && typeof svc.request === 'function');
}

/** 凭据服务（按操作现取，语义见 index.js 的 credentials 注释）。 */
export function resolveCredentials(ctx) {
  return optionalService(ctx, 'credentials');
}
