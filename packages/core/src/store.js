/**
 * 存储层 —— 原子写 + **机制化拒密**（DESIGN.md §3 D4 / §7.1 / §11.4）。
 *
 * 最重要的一点：`assertSecretFree()` 用代码强制「凭据不落地」，
 * 而不是靠开发者自觉。任何写入 targets.json / policy.json 的对象，
 * 只要出现敏感键名或私钥内容，立刻抛错。
 */

import { mkdir, readFile, rename, writeFile, chmod } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

/**
 * 已知安全的**元数据**键：它们"看起来像"凭据，但描述的是认证方式/路径/算法，不含秘密。
 *
 * 为什么需要这个白名单（推演发现 F7）：单纯把拒绝规则写成子串匹配会误伤
 * `passwordAuth` / `pubkeyAuth` / `authKind` / `privateKeyPath` 这些合法字段 ——
 * 而 facts 里就有 `ssh.passwordAuth`。所以采用「白名单优先，再按后缀拒绝」。
 */
const SAFE_METADATA_KEYS = new Set([
  'passwordauth', 'pubkeyauth', 'authkind', 'authref', 'authmode', 'authtype',
  'privatekeypath', 'hostkey', 'keyalgo', 'keytype', 'fingerprint',
]);

/** 归一化键名：小写 + 去掉分隔符。 */
function normKey(key) {
  return key.toLowerCase().replace(/[-_\s]/g, '');
}

/**
 * 拒绝后缀：键名以这些词**结尾**即视为凭据载体。
 *
 * 用后缀而不是子串，是为了既覆盖 `secretKey`/`accessKey`/`sessionToken` 这些
 * 原黑名单漏掉的名字，又不至于把任意含 "key" 的键（如 `hostKey`）一网打尽。
 * 刻意不含 `pat` —— 它会让 `compat` 之类的键误伤。
 */
const DENY_SUFFIXES = [
  'password', 'passwd', 'passphrase', 'secret', 'token',
  'apikey', 'accesskey', 'secretkey', 'privatekey',
  'credential', 'credentials', 'bearer', 'pin',
];

/** 值层面的私钥特征。 */
const PEM_PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const OPENSSH_PRIVATE_KEY = /-----BEGIN OPENSSH PRIVATE KEY-----/;

/**
 * 判断一个键名是否属于"秘密载体"。
 *
 * **这是该判定的唯一实现** —— `assertSecretFree`（写入拒绝）与 `redact.js`
 * （输出脱敏）都调用它。两处若各写一套规则，迟早会漂移成"一边拦一边放"。
 */
export function isSecretKeyName(key) {
  if (typeof key !== 'string') return false;
  const norm = normKey(key);
  if (SAFE_METADATA_KEYS.has(norm)) return false;
  return DENY_SUFFIXES.some((suffix) => norm.endsWith(suffix));
}

/**
 * 递归检查对象中不含凭据。**键名与值双路检查**。
 * @param {unknown} value
 * @param {string} [path] 仅用于错误定位。
 * @throws {Error} 发现疑似凭据时抛出（fail closed，绝不静默剔除）。
 */
export function assertSecretFree(value, path = '$') {
  if (value === null || value === undefined) return;
  if (typeof value === 'string') {
    if (PEM_PRIVATE_KEY.test(value) || OPENSSH_PRIVATE_KEY.test(value)) {
      throw new Error(`拒绝写入疑似私钥内容：${path}（凭据只允许存放引用 authRef）`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertSecretFree(item, `${path}[${i}]`));
    return;
  }
  if (typeof value === 'object') {
    for (const [key, val] of Object.entries(value)) {
      if (isSecretKeyName(key)) {
        throw new Error(
          `拒绝写入敏感字段 "${key}"（位于 ${path}）。` +
          '凭据必须存于凭据库，此处只允许 authRef 引用。' +
          '（若这是描述认证方式的元数据，请加入 SAFE_METADATA_KEYS 白名单）',
        );
      }
      assertSecretFree(val, `${path}.${key}`);
    }
  }
}

/**
 * 校验 id 可用于文件路径。
 *
 * 推演发现 F6：targetId 会被用于拼报告/运行记录的落盘路径
 * （`reports/<targetId>/<YYYY>/<YYYY-MM-DD>.json`），不校验就是写盘路径穿越。
 * 规则刻意收紧到「首字符字母数字 + 只允许 . _ -」，因此 `..`、`/`、`\`、`:`、空格一律拒绝。
 *
 * @param {unknown} id
 * @param {string} [label] 出错信息里用的字段名
 */
export function assertSafeId(id, label = 'id') {
  if (typeof id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id)) {
    throw new Error(
      `${label} 非法：${JSON.stringify(id)}。` +
      '只允许字母数字开头、由 [A-Za-z0-9._-] 组成、长度 ≤64 的标识（该值会出现在文件路径中）。',
    );
  }
  return id;
}

/** 原子写 JSON：先写临时文件再 rename，避免半截文件。 */
export async function writeJsonAtomic(filePath, value) {
  await mkdir(dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await rename(tmp, filePath);
  // POSIX 上收紧权限；Windows 无 chmod 语义会静默失败，故容错。
  try {
    await chmod(filePath, 0o600);
  } catch {
    /* Windows / 无权限：忽略，安全性依赖 profile ACL + 凭据不落地 */
  }
}

async function readJson(filePath, fallback) {
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch (err) {
    if (err && err.code === 'ENOENT') return fallback;
    throw err;
  }
}

/**
 * 打开一个存储目录。
 *
 * **同步**创建目录：插件 `apply()` 需要同步拿到 store 句柄。
 * 读写仍为异步（在工具 execute 里调用）。
 * @param {{ dir: string }} options
 */
export function openStore({ dir }) {
  mkdirSync(dir, { recursive: true });
  const paths = {
    targets: join(dir, 'targets.json'),
    policy: join(dir, 'policy.json'),
  };

  return {
    dir,
    paths,

    async readTargets() {
      return readJson(paths.targets, { schema: 'vmprobe/targets/1', targets: [] });
    },

    async writeTargets(doc) {
      assertSecretFree(doc);
      const next = { ...doc, schema: 'vmprobe/targets/1' };
      await writeJsonAtomic(paths.targets, next);
      return next;
    },

    async readPolicy() {
      return readJson(paths.policy, { schema: 'vmprobe/policy/1' });
    },

    async writePolicy(doc) {
      assertSecretFree(doc);
      const next = { ...doc, schema: 'vmprobe/policy/1' };
      await writeJsonAtomic(paths.policy, next);
      return next;
    },
  };
}

/**
 * 构造一个不含凭据的 Target 记录（只留 authRef 引用）。
 * 所有创建路径都必须经过它，避免手写对象时误带凭据。
 */
export function makeTarget(input) {
  const {
    id, label, hostname, port = 22, user,
    authKind = 'password', authRef,
    fingerprint, keyAlgo = 'ssh-ed25519',
    tags = [], transport = 'embedded',
  } = input;
  if (!id || !hostname || !user) throw new Error('makeTarget 需要 id / hostname / user');
  if (!authRef) throw new Error('makeTarget 需要 authRef（凭据引用，而非凭据本身）');

  // ★ authRef 必须是**引用字符串**，这里显式拒绝对象。
  //
  // 踩过一次（M2 阶段由真实 SSH 检查抓出）：调用方把"已完成规范化的目标形状"
  // （`authRef: { kind, ref }`）当成**输入**再喂进来，于是 ref 变成了对象，
  // 产出的目标里是 `ref: { kind, ref: '...' }`。在宽松的凭据解析器下它**照样能连上**，
  // 于是错误一路潜伏到某个严格解析器上才炸，且报错信息是"凭据 [object Object] 尚未配置" ——
  // 完全指不到真正的原因。这类"能跑但形状错了"的输入必须在边界上就拒掉。
  if (typeof authRef !== 'string' || !authRef.trim()) {
    throw new Error(
      `makeTarget 的 authRef 必须是非空字符串引用，实际 ${JSON.stringify(authRef)}。`
      + '如果你手上是已完成规范化的目标对象（{ authRef: { kind, ref } }），'
      + '请传 `authRef: that.authRef.ref, authKind: that.authRef.kind`，不要把整个对象再传一次。',
    );
  }

  // id 会进入文件路径（报告/运行记录），必须收紧
  assertSafeId(id, 'target.id');
  if (!['password', 'key', 'agent'].includes(authKind)) {
    throw new Error(`authKind 必须是 password | key | agent，实际 ${JSON.stringify(authKind)}`);
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`port 必须是 1..65535 的整数，实际 ${JSON.stringify(port)}`);
  }
  const target = {
    id,
    label: label ?? hostname,
    hostname,
    port,
    user,
    authRef: { kind: authKind, ref: authRef },
    hostKey: fingerprint
      ? { algo: keyAlgo, fingerprint, trust: 'pinned', pinnedAt: new Date().toISOString() }
      : { algo: keyAlgo, fingerprint: null, trust: 'unverified' },
    transport,
    tags: [...tags],
    agent: null,
    lastSeenAt: null,
  };
  assertSecretFree(target);
  return target;
}
