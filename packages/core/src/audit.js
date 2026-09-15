/**
 * 审计哈希链 —— 让双端日志可交叉核对、且篡改可检出（DESIGN.md §7.3）。
 *
 * 关键性质：
 *   - 规范化 JSON（键排序）保证同一记录在不同平台/进程算出的哈希一致；
 *   - 每条记录带 `prev`（前一条哈希）+ `hash`（自身 + prev）；
 *   - 篡改任意一条，其后所有记录断链；
 *   - 主控端与协从端各自独立记录同一次 run，交叉比对即可发现单侧伪造。
 *
 * ── HMAC 加固（M5）：从"能检出改动"升级到"能抗伪造" ────────────────────────
 *
 * 无密钥的 sha256 链有个诚实的局限：**拥有审计目录写权限、且愿意重算整条链的攻击者可以伪造**
 * （重算一遍，链就自洽了）。加密钥之后，伪造需要**密钥**，而不只是写权限。
 *
 * 三条设计决定：
 *   ① **逐条记 `algo`**：老记录没有该字段（等价于 `sha256`），新记录是 `hmac-sha256`，
 *      因此**旧链照样能验**，不需要迁移，也不假装历史被密钥保护过。
 *   ② **`algo` 与 `keyId` 都进哈希正文**：否则攻击者可以把 `algo` 改成 `sha256` 再用无密钥
 *      方式重算，做成"一步降级"；进了正文之后，改 algo 必然导致哈希不符。
 *   ③ **禁止降级**：链里一旦出现 hmac 记录，其后不得再出现 sha256 记录，验链时报 `downgradeAt`。
 *      这条规则让 ② 无法被"改 algo + 重算"绕过。
 *      （`keyId` 是密钥的 sha256 前缀，**不是密钥**，可以安全进日志。）
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';

/** 链首的 prev 值。 */
export const GENESIS = '0'.repeat(64);

/** 两种算法标识。缺 `algo` 字段即视为 `sha256`（旧格式）。 */
export const ALGO_SHA256 = 'sha256';
export const ALGO_HMAC = 'hmac-sha256';

/** 密钥指纹：密钥的 sha256 前 16 位。**可以**进日志（不是密钥本身）。 */
export function keyIdOf(key) {
  return key ? createHash('sha256').update(String(key), 'utf8').digest('hex').slice(0, 16) : null;
}

/** 生成一把 32 字节随机审计密钥（十六进制）。 */
export function generateAuditKey() {
  return randomBytes(32).toString('hex');
}

/**
 * 确定性 JSON 序列化（递归键排序）。
 * 时间戳/字段顺序不能被写入方随意影响，否则哈希不可比。
 */
export function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('审计记录不允许非有限数值');
    return JSON.stringify(value);
  }
  if (t === 'string' || t === 'boolean') return JSON.stringify(value);
  if (t === 'bigint') throw new Error('审计记录不允许 bigint');
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new Error(`审计记录不允许的类型: ${t}`);
}

/**
 * 计算一条记录的哈希（含 prev 绑定）。
 *
 * @param {string} prevHash
 * @param {object} record
 * @param {string|null} [key] 有密钥则 HMAC-SHA256，否则纯 SHA-256（旧格式）
 * @param {string|null} [algo] 显式算法。**校验时必须显式传**，
 *   而不是靠"当前有没有配密钥"来猜 —— 否则换密钥后旧记录会被误判成被篡改。
 */
export function hashRecord(prevHash, record, key = null, algo = null) {
  if (typeof prevHash !== 'string' || prevHash.length !== 64) {
    throw new Error('prevHash 必须是 64 位十六进制字符串');
  }
  const body = `${prevHash}\n${canonicalJson(record)}`;
  const useHmac = (algo ?? (key ? ALGO_HMAC : ALGO_SHA256)) === ALGO_HMAC;
  if (useHmac) {
    if (!key) throw new Error('记录声明为 hmac-sha256 但未提供密钥 —— 无法校验，也不假装能验');
    return createHmac('sha256', String(key)).update(body).digest('hex');
  }
  return createHash('sha256').update(body).digest('hex');
}

/** 对一个字符串求 sha256（用于给报告文件等内容盖章）。 */
export function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * 把一条记录追加进链，返回带 `prev`/`hash` 的新记录。
 * 不修改入参（记录会被冻结在会话/日志两侧复用）。
 *
 * 配了密钥时，记录会带上 `algo` 与 `keyId`（**两者都参与哈希**）。
 */
export function chainRecord(prevHash, record, key = null) {
  const body = { ...record };
  delete body.prev;
  delete body.hash;
  if (key) {
    body.algo = ALGO_HMAC;
    body.keyId = keyIdOf(key);
  }
  return { ...body, prev: prevHash, hash: hashRecord(prevHash, body, key, body.algo ?? ALGO_SHA256) };
}

/**
 * 从一组已上链记录推导出「下一条的 prev」。
 * @param {object[]} records 记录窗口
 * @param {string} [fallback] 窗口为空时用的锚（默认 GENESIS）
 */
export function tailHash(records, fallback = GENESIS) {
  if (!Array.isArray(records) || records.length === 0) return fallback;
  return records[records.length - 1].hash;
}

/**
 * 校验整条链。
 *
 * @param {object[]} records
 * @param {string} [expectedPrev] 期望的起点 prev。默认 GENESIS。
 *   当内存里只保留链的尾部窗口（见 `createAuditLog` 的 `maxRecords`）时，
 *   窗口首条的 prev 是"被裁掉那条"的哈希，因此必须显式传入锚点 ——
 *   否则裁剪本身会被误报成"链已损坏"。
 * @param {{ key?: string|null, keyId?: string|null, requireHmac?: boolean }} [opts]
 *   `requireHmac: true` 表示"我知道这台机器启用过密钥" —— 于是"链里一条 hmac 记录都没有"
 *   本身就是异常（可能是整段历史被降级重写）。默认 false：引擎无法区分
 *   "这是启用密钥之前的历史"与"历史被整段重写过"，因此不替用户下这个判断。
 */
export function verifyChain(records, expectedPrev = GENESIS, opts = {}) {
  if (!Array.isArray(records)) {
    return { ok: false, reason: '记录集不是数组', length: 0, forgeryResistant: false, hmacCount: 0, legacyCount: 0 };
  }
  const key = opts.key ?? null;
  const wantKeyId = opts.keyId ?? keyIdOf(key);
  const requireHmac = opts.requireHmac === true;

  let prev = expectedPrev;
  let hmacCount = 0;
  let legacyCount = 0;
  let sawHmac = false;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    if (rec === null || typeof rec !== 'object') {
      return { ok: false, brokenAt: i, reason: '记录不是对象', length: records.length, hmacCount, legacyCount, forgeryResistant: false };
    }
    if (rec.prev !== prev) {
      return {
        ok: false,
        brokenAt: i,
        reason: `prev 不匹配：期望 ${prev.slice(0, 12)}…，实际 ${String(rec.prev).slice(0, 12)}…`,
        length: records.length, hmacCount, legacyCount, forgeryResistant: false,
      };
    }

    const algo = rec.algo ?? ALGO_SHA256;
    if (algo !== ALGO_SHA256 && algo !== ALGO_HMAC) {
      return {
        ok: false, brokenAt: i, reason: `未知的 algo：${JSON.stringify(algo)}`,
        length: records.length, hmacCount, legacyCount, forgeryResistant: false,
      };
    }

    // ③ 禁止降级
    if (algo === ALGO_SHA256 && sawHmac) {
      return {
        ok: false,
        brokenAt: i,
        downgradeAt: i,
        reason: `第 ${i} 条从 hmac-sha256 退回 sha256 —— 不允许降级`
          + '（否则"把 algo 改成 sha256 再重算"就能绕过密钥保护）',
        length: records.length, hmacCount, legacyCount, forgeryResistant: false,
      };
    }

    const body = { ...rec };
    delete body.prev;
    delete body.hash;

    if (algo === ALGO_HMAC) {
      sawHmac = true;
      hmacCount += 1;
      // 换过密钥：当前密钥验不了旧密钥签的记录 —— 如实报"验不了"，**不报成"被篡改"**
      if (rec.keyId && wantKeyId && rec.keyId !== wantKeyId) {
        return {
          ok: false,
          brokenAt: i,
          keyMismatchAt: i,
          reason: `第 ${i} 条由密钥 ${rec.keyId} 签署，当前密钥是 ${wantKeyId} —— 无法校验`
            + '（这**不等于**被篡改；请提供原密钥，或接受"这一段不可验证"）',
          length: records.length, hmacCount, legacyCount, forgeryResistant: false,
        };
      }
      if (!key) {
        return {
          ok: false,
          brokenAt: i,
          keyMissingAt: i,
          reason: `第 ${i} 条是 hmac-sha256 记录但没有提供密钥 —— 无法校验`,
          length: records.length, hmacCount, legacyCount, forgeryResistant: false,
        };
      }
    } else {
      legacyCount += 1;
    }

    const expect = hashRecord(prev, body, key, algo);
    if (rec.hash !== expect) {
      return {
        ok: false,
        brokenAt: i,
        reason: `内容被改动：期望 ${expect.slice(0, 12)}…，实际 ${String(rec.hash).slice(0, 12)}…`,
        length: records.length, hmacCount, legacyCount, forgeryResistant: false,
      };
    }
    prev = rec.hash;
  }

  return {
    ok: true,
    length: records.length,
    hmacCount,
    legacyCount,
    // 只有整条链都被密钥保护时才叫"抗伪造"；混有旧记录时如实说明
    forgeryResistant: hmacCount > 0 && legacyCount === 0,
    // 显式要求 HMAC 却一条都没有：**这不能靠链自身判定**（整段重写会抹掉所有 hmac 痕迹），
    // 因此只在调用方明确知道"本机启用过密钥"时（requireHmac）才报出来。
    ...(requireHmac && hmacCount === 0 && records.length > 0
      ? {
        ok: false,
        unkeyedEntirely: true,
        reason: `链里没有任何 hmac-sha256 记录（共 ${records.length} 条），但调用方声明本机启用过密钥 —— `
          + '要么这些是启用密钥之前的旧历史，要么整段历史被降级重写过。'
          + '链自身无法区分这两者（重写会抹掉 hmac 痕迹），需要外部旁证（如别处留存的 keyId / config.effective 快照）。',
      }
      : {}),
  };
}

/**
 * 内存态追加器。
 *
 * `maxRecords` 是必须的（推演发现 F12）：心跳类 R0 记录会线性堆积
 * （60s 一次 → 一年约 52 万条），且每条都要算一次 SHA-256，最终变成内存与 CPU 双重泄漏。
 * 因此内存只保留链的**尾部窗口**，完整历史交给落盘（JSONL）。
 *
 * 裁剪后链的可校验窗口也随之变窄 —— 这是真实存在的取舍，不能假装没有：
 * `verify()` 会一并返回 `truncated`（被裁掉的条数），`anchor` 是被裁部分的尾哈希，
 * 因此"从窗口起点至今未被篡改"仍可验证。
 *
 * @param {{ maxRecords?: number, key?: string|null }} [options]
 *   `key` 存在时新记录用 HMAC；**装载历史（hydrate）不受影响** ——
 *   历史记录的算法由它们自己的 `algo` 字段决定，因此换密钥不会让旧链"变脏"。
 */
export function createAuditLog(options = {}) {
  const maxRecords = Number.isInteger(options.maxRecords) && options.maxRecords > 0
    ? options.maxRecords
    : 5000;
  /** 审计密钥。刻意允许为空：没密钥就是旧行为（可检出改动，但不能抗伪造）。 */
  let key = options.key ?? null;

  const records = [];
  /** 被裁掉部分最后一条的哈希；窗口校验的起点锚。 */
  let anchor = GENESIS;
  let truncated = 0;
  let total = 0;

  return {
    maxRecords,

    /** 追加一条记录。 */
    append(record) {
      const chained = chainRecord(tailHash(records, anchor), { ts: new Date().toISOString(), ...record }, key);
      records.push(chained);
      total++;
      while (records.length > maxRecords) {
        anchor = records.shift().hash;
        truncated++;
      }
      return chained;
    },

    /**
     * 装载**已经上链**的历史记录（用于重启后重放 JSONL）。
     *
     * 与 `append()` 的区别很关键：这里必须原样保留 `ts`/`hash`，
     * 因为重新上链会改变时间戳与哈希，从而破坏"历史证据"的价值。
     * 装载后同样套用内存上限。
     *
     * @param {object[]} loaded 已含 prev/hash 的记录
     */
    hydrate(loaded) {
      if (!Array.isArray(loaded) || loaded.length === 0) return;
      for (const rec of loaded) records.push(rec);
      total += loaded.length;
      while (records.length > maxRecords) {
        anchor = records.shift().hash;
        truncated++;
      }
    },

    /** 只读快照（内存中保留的窗口）。 */
    snapshot() {
      return records.map((r) => ({ ...r }));
    },

    /** 校验保留窗口内的链完整性。 */
    verify() {
      return { ...verifyChain(records, anchor, { key }), truncated, total, keyId: keyIdOf(key), keyed: Boolean(key) };
    },

    /** 当前使用的密钥指纹（可安全展示；不是密钥本身）。 */
    get keyId() {
      return keyIdOf(key);
    },

    /**
     * 切换审计密钥。
     *
     * ⚠️ **只允许在"本进程尚未写过 hmac 记录"时切换**。因为链里已经存在的 hmac 记录是用旧密钥
     * 签的，换掉之后那些记录就**再也验不了**（`verifyChain` 会如实报 `keyMismatchAt`，
     * 而不是谎报"链坏了"）。要在已有 hmac 历史的机器上换密钥，必须走**显式的轮换流程**
     * （保留旧密钥用于验旧段），那是运维动作，不该由一个 setter 顺手做掉。
     *
     * @returns {{ok: boolean, reason?: string, keyId: string|null}}
     */
    setKey(nextKey) {
      const alreadyHmac = records.some((r) => (r.algo ?? ALGO_SHA256) === ALGO_HMAC);
      if (alreadyHmac && keyIdOf(nextKey) !== keyIdOf(key)) {
        return {
          ok: false,
          reason: '链里已有 hmac 记录，不能在运行中直接换密钥（旧记录将无法校验）；请走密钥轮换流程',
          keyId: keyIdOf(key),
        };
      }
      key = nextKey ?? null;
      return { ok: true, keyId: keyIdOf(key) };
    },

    /** 当前窗口起点锚（落盘/交叉核对时有用）。 */
    get anchor() {
      return anchor;
    },

    get length() {
      return records.length;
    },

    /** 历史累计条数（含已被裁掉的）。 */
    get total() {
      return total;
    },
  };
}
