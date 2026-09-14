/**
 * 动作参数校验与归一化 —— 补上被 `defineTool` 跳过的那一环。
 *
 * 背景（M0 推演发现 F5）：插件直接构造 ToolDefinition（为可测试性绕开了 `defineTool`），
 * 因此 DSH 的 `validateArgs` 不会执行；而动作目录里的 `params` schema 也没有任何地方消费。
 * 结果是任意键值都能流进审计与后续执行 —— 一旦参数接线，就是注入面。
 *
 * 本模块是**显式、可单测**的替代实现，规则与目录里的 JSON Schema 对齐。
 */

/** 单值类型校验。 */
function checkType(value, schema) {
  switch (schema.type) {
    case 'boolean':
      return typeof value === 'boolean' ? null : '应为布尔值';
    case 'string':
      return typeof value === 'string' ? null : '应为字符串';
    case 'integer':
      return Number.isInteger(value) ? null : '应为整数';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value) ? null : '应为有限数值';
    case 'array':
      return Array.isArray(value) ? null : '应为数组';
    case 'object':
      return value !== null && typeof value === 'object' && !Array.isArray(value) ? null : '应为对象';
    default:
      return null; // 未声明类型：不限制
  }
}

/**
 * 校验动作参数。
 * @param {object} action 动作定义
 * @param {object} params 调用方给出的参数
 * @returns {string[]} 错误列表（空数组表示通过）
 */
export function validateParams(action, params = {}) {
  const errors = [];
  if (params === null || typeof params !== 'object' || Array.isArray(params)) {
    return ['params 必须是对象'];
  }

  const schema = action?.params ?? null;
  const props = schema?.properties ?? {};
  const known = Object.keys(props);

  for (const key of Object.keys(params)) {
    if (!known.includes(key)) {
      errors.push(`未知参数 "${key}"（该动作接受：${known.join(', ') || '无'}）`);
      continue;
    }
    const err = checkType(params[key], props[key]);
    if (err) errors.push(`参数 "${key}" ${err}`);
    if (Array.isArray(props[key].enum) && !props[key].enum.includes(params[key])) {
      errors.push(`参数 "${key}" 必须是 ${props[key].enum.join(' / ')} 之一`);
    }
    if (props[key].type === 'array' && props[key].items?.type && Array.isArray(params[key])) {
      const itemErr = checkType(params[key][0], props[key].items);
      if (itemErr && params[key].length > 0) errors.push(`参数 "${key}" 的元素${itemErr}`);
    }
  }

  // 必填判定同时支持两种写法：
  //   · JSON Schema 标准：对象级 `required: ["a","b"]`
  //   · DSH 的 ParameterSchemaSpec 风格：逐属性 `required: true`
  // 目录作者从任一种习惯写来都应被正确识别。
  const requiredKeys = new Set(schema?.required ?? []);
  for (const [key, prop] of Object.entries(props)) {
    if (prop?.required === true) requiredKeys.add(key);
  }
  for (const key of requiredKeys) {
    if (params[key] === undefined && props[key]?.default === undefined) {
      errors.push(`缺少必填参数 "${key}"`);
    }
  }

  return errors;
}

/** 深比较（仅用于与 default 比对；参数都是 lossless JSON）。 */
function sameValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * 归一化参数：把"与 schema 默认值相同"的键去掉。
 *
 * 理由：显式传 `{ section: 'all' }` 与不传应视为同一件事，
 * 否则"未接线的参数"检查会把等价于默认值的显式传参误判为需要接线。
 */
export function normalizeParams(action, params = {}) {
  const props = action?.params?.properties ?? {};
  const out = {};
  for (const [key, value] of Object.entries(params)) {
    const def = props[key]?.default;
    if (def !== undefined && sameValue(value, def)) continue;
    out[key] = value;
  }
  return out;
}

/**
 * 找出"已声明但执行器尚未消费"的参数。
 *
 * 这是防"谎报行为"的关键（推演发现 F2）：目录声明了 `securityOnly`
 * 而实现忽略它时，用户以为只装安全更新、实际执行全量升级 —— 比直接报错更危险。
 * 因此策略是 **fail-closed**：未接线的参数一出现就阻断，而不是默默忽略。
 *
 * @param {object} action 动作定义
 * @param {object} params 原始参数
 * @param {string[]|null} [consumed] **权威来源**：`resolveCommands()` 从 argv 里实际引用到的参数名。
 *   传了它就以它为准 —— 接线情况是"用出来"的，不是作者声明出来的，
 *   所以只要某个参数没被任何 argv 元素引用，就一定会被拦下。
 *   仅在拿不到 argv 分析结果时才回退到旧的静态 `wiredParams`（已废弃）。
 * @returns {string[]} 未接线的参数名
 */
export function findUnwiredParams(action, params = {}, consumed = null) {
  const wired = consumed !== null && consumed !== undefined
    ? new Set(consumed)
    : new Set(action?.wiredParams ?? []);
  const normalized = normalizeParams(action, params);
  return Object.keys(normalized).filter((k) => !wired.has(k));
}
