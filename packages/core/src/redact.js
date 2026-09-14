/**
 * 统一脱敏 —— 落盘与呈现之前必须过的唯一关口。
 *
 * 为什么需要它（推演发现 I8）：
 *   `store.js` 的 `assertSecretFree` 只保护**我们自己写的结构化数据**（targets/policy）。
 *   但秘密还会从两条完全不同的路径漏出去：
 *     ① **错误文本**：传输层/远端命令抛出的错误里可能带 argv、带远端回显；
 *     ② **审计字段**：params、resolvedArgv 等自由字段可能被塞进敏感值。
 *   原来这两条路都没有过滤 —— 是个真实缺口。
 *
 * 设计取舍：
 *   · **脱敏发生在写入之前**，因此哈希链覆盖的是脱敏后的内容。这是刻意的：
 *     审计要能证明"发生过什么"，而**不能**成为秘密的第二个副本。
 *   · 但要**保留"此处曾被脱敏"的事实** —— `redactDeep` 返回 `redactedPaths`，
 *     由调用方记进审计。这样既看不到秘密，又知道秘密曾经经过。
 *     这个区别很重要：完全抹掉痕迹会让"秘密曾经流经这里"变得不可发现。
 *   · 幂等：重复脱敏结果不变（替换标记本身不会再被匹配）。
 */

import { isSecretKeyName } from './store.js';

/** 值层面的模式。顺序有意义：私钥块最先，避免块内内容被后续规则拆散。 */
const VALUE_PATTERNS = [
  {
    kind: 'private-key',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    mask: () => '[REDACTED:private-key]',
  },
  {
    kind: 'jwt',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    mask: () => '[REDACTED:jwt]',
  },
  {
    // scheme://user:pass@host → 保留 scheme 与 @，只吃凭据
    kind: 'url-credentials',
    re: /\b([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi,
    mask: (_m, scheme) => `${scheme}[REDACTED:url-credentials]@`,
  },
  {
    // 命令行形态：curl -u user:pass / --user user:pass
    // 单测发现这是真实的泄漏路径 —— "-u user:pw" 不在 URL 里，原来的 url 规则抓不到。
    // 该模式只匹配"标志 + 含冒号的值"，因此 "-u root"（无冒号）不会被误伤。
    kind: 'cli-credentials',
    re: /(\s-{1,2}(?:u|user|password|pass)\s+)[^\s:]+:\S+/gi,
    mask: (_m, flag) => `${flag}[REDACTED:cli-credentials]`,
  },
  {
    // HTTP 头形态：`Authorization: Bearer <token>`
    // 日志里转储请求头是最常见的泄漏路径之一，而它没有 `key=value` 结构，
    // 上面那条 key-value 规则抓不到（`Bearer` 与 token 之间是空格而非 : 或 =）。
    kind: 'bearer-token',
    re: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    mask: () => 'Bearer [REDACTED:bearer-token]',
  },
  {
    kind: 'aws-access-key',
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    mask: () => '[REDACTED:aws-access-key]',
  },
  {
    // key=value / "key": "value" / 'key': 'value'
    //
    // 两个单测逼出来的细节：
    //  ① 必须容忍键名两侧的**引号** —— JSON 里是 `"token": "x"`，
    //     而最初只写 `token\s*[:=]` 完全抓不到，这恰恰是最常见的形态。
    //     而且这里**不能用 `\b`**：`{` 与 `"` 之间没有单词边界，`{"token"` 会直接匹配失败；
    //     改用负向后顾（前面不是标识符字符），既让带引号的键能匹配，
    //     又避免在 `mypassword=` 这类长标识符内部误匹配。
    //  ② 必须有负向先行 `(?!\[REDACTED)` —— 否则第二遍会把 `[REDACTED:key-value`
    //     再当成一次值，输出累积成 `...value]]`，破坏幂等。
    //  ④ 必须**显式列举常见复合名**（access_token / refresh_token / client_secret …）。
    //     因为负向后顾挡住了 `_` 开头的匹配（为了不误伤 `mypassword`），
    //     副作用就是 `access_token` 里的 `token` 也进不来 —— 而这类名字极常见。
    //     复合形式写在裸名之前，保证整体匹配。
    kind: 'key-value',
    re: /(?<![A-Za-z0-9_])(["']?)((?:client[_-]?secret|secret[_-]?key|api[_-]?key|access[_-]?key|private[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?token|id[_-]?token|auth[_-]?token|bearer[_-]?token)|password|passwd|pwd|passphrase|secret|token|bearer)\1(\s*[:=]\s*)(?!\[REDACTED)("[^"]*"|'[^']*'|[^\s,;"'}\]]+)/gi,
    mask: (_m, quote, key, sep, val) => {
      const q = quote ?? '';
      if (val.startsWith('"') || val.startsWith("'")) {
        return `${q}${key}${q}${sep}${val[0]}[REDACTED:key-value]${val[0]}`;
      }
      return `${q}${key}${q}${sep}[REDACTED:key-value]`;
    },
  },
];

/** 最短可登记长度：太短的值做字面替换会误伤正常文本。 */
const MIN_REGISTERED_LENGTH = 4;

/**
 * 脱敏一段文本。
 * @param {unknown} input
 * @param {{ registered?: string[] }} [options] 运行时已知的秘密值（精确字面替换）
 */
export function redactText(input, options = {}) {
  if (input === null || input === undefined) return input;
  let s = typeof input === 'string' ? input : String(input);

  // 先做运行时登记值（通常是刚用过的密码），再做模式匹配
  for (const secret of options.registered ?? []) {
    if (typeof secret === 'string' && secret.length >= MIN_REGISTERED_LENGTH) {
      s = s.split(secret).join('[REDACTED:registered]');
    }
  }

  for (const { re, mask } of VALUE_PATTERNS) {
    re.lastIndex = 0;
    s = s.replace(re, mask);
  }
  return s;
}

/**
 * 递归脱敏一个值。
 *
 * 两条规则并用：
 *   · **键名**是秘密载体（`isSecretKeyName`，与 store 的拒密共用同一套判定）→ 整个值替换；
 *   · **值**命中模式（私钥/JWT/URL 凭据/…）→ 就地替换。
 *
 * @returns {{ value: unknown, redactedPaths: string[] }}
 */
export function redactDeep(value, options = {}) {
  const redactedPaths = [];
  const registered = options.registered ?? [];

  const walk = (node, path) => {
    if (node === null || node === undefined) return node;

    if (typeof node === 'string') {
      const out = redactText(node, { registered });
      if (out !== node) redactedPaths.push(path);
      return out;
    }
    if (typeof node === 'number' || typeof node === 'boolean') return node;
    if (typeof node === 'bigint') return node.toString();
    if (Array.isArray(node)) return node.map((item, i) => walk(item, `${path}[${i}]`));
    if (typeof node === 'object') {
      const out = {};
      for (const [key, val] of Object.entries(node)) {
        const childPath = `${path}.${key}`;
        if (isSecretKeyName(key)) {
          out[key] = '[REDACTED:key-name]';
          redactedPaths.push(`${childPath}#key`);
          continue;
        }
        out[key] = walk(val, childPath);
      }
      return out;
    }
    return '[REDACTED:unsupported]';
  };

  const result = walk(value, options.rootPath ?? '$');
  return { value: result, redactedPaths };
}

/**
 * 创建一个带运行时秘密登记表的脱敏器。
 *
 * 用途：认证切换过程中密码短暂存在于内存，此时任何日志/错误都可能把它带出去。
 * 登记后所有经过该脱敏器的文本都会把它替换掉 —— 并在用完后 `clear()`。
 */
export function createRedactor() {
  /** @type {Set<string>} */
  const registered = new Set();

  return {
    /** 登记一个秘密值（<4 字符会被忽略，避免误伤正常文本）。 */
    add(secret) {
      if (typeof secret === 'string' && secret.length >= MIN_REGISTERED_LENGTH) registered.add(secret);
    },
    /** 用完即清（例如认证切换完成后）。 */
    clear() {
      registered.clear();
    },
    get size() {
      return registered.size;
    },
    text(input) {
      return redactText(input, { registered: [...registered] });
    },
    deep(value, rootPath) {
      return redactDeep(value, { registered: [...registered], rootPath });
    },
    /** 脱敏一个 Error，保留名称与栈的形状。 */
    error(err) {
      if (!err) return err;
      const out = new Error(redactText(err.message ?? String(err), { registered: [...registered] }));
      out.name = err.name ?? 'Error';
      if (err.code) out.code = err.code;
      return out;
    },
  };
}
