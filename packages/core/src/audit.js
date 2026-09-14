/**
 * 审计哈希链 —— 让双端日志可交叉核对、且篡改可检出（DESIGN.md §7.3）。
 *
 * 关键性质：
 *   - 规范化 JSON（键排序）保证同一记录在不同平台/进程算出的哈希一致；
 *   - 每条记录带 `prev`（前一条哈希）+ `hash`（自身 + prev）；
 *   - 篡改任意一条，其后所有记录断链；
 *   - 主控端与协从端各自独立记录同一次 run，交叉比对即可发现单侧伪造。
 */

import { createHash } from 'node:crypto';

/** 链首的 prev 值。 */
export const GENESIS = '0'.repeat(64);

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

/** 计算一条记录的哈希（含 prev 绑定）。 */
export function hashRecord(prevHash, record) {
  if (typeof prevHash !== 'string' || prevHash.length !== 64) {
    throw new Error('prevHash 必须是 64 位十六进制字符串');
  }
  return createHash('sha256').update(prevHash).update('\n').update(canonicalJson(record)).digest('hex');
}

/** 对一个字符串求 sha256（用于给报告文件等内容盖章）。 */
export function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * 把一条记录追加进链，返回带 `prev`/`hash` 的新记录。
 * 不修改入参（记录会被冻结在会话/日志两侧复用）。
 */
export function chainRecord(prevHash, record) {
  const body = { ...record };
  delete body.prev;
  delete body.hash;
  return { ...body, prev: prevHash, hash: hashRecord(prevHash, body) };
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
 */
export function verifyChain(records, expectedPrev = GENESIS) {
  if (!Array.isArray(records)) return { ok: false, reason: '记录集不是数组', length: 0 };
  let prev = expectedPrev;
  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    if (rec === null || typeof rec !== 'object') {
      return { ok: false, brokenAt: i, reason: '记录不是对象', length: records.length };
    }
    if (rec.prev !== prev) {
      return {
        ok: false,
        brokenAt: i,
        reason: `prev 不匹配：期望 ${prev.slice(0, 12)}…，实际 ${String(rec.prev).slice(0, 12)}…`,
        length: records.length,
      };
    }
    const body = { ...rec };
    delete body.prev;
    delete body.hash;
    const expect = hashRecord(prev, body);
    if (rec.hash !== expect) {
      return {
        ok: false,
        brokenAt: i,
        reason: `内容被改动：期望 ${expect.slice(0, 12)}…，实际 ${String(rec.hash).slice(0, 12)}…`,
        length: records.length,
      };
    }
    prev = rec.hash;
  }
  return { ok: true, length: records.length };
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
 * @param {{ maxRecords?: number }} [options]
 */
export function createAuditLog(options = {}) {
  const maxRecords = Number.isInteger(options.maxRecords) && options.maxRecords > 0
    ? options.maxRecords
    : 5000;

  const records = [];
  /** 被裁掉部分最后一条的哈希；窗口校验的起点锚。 */
  let anchor = GENESIS;
  let truncated = 0;
  let total = 0;

  return {
    maxRecords,

    /** 追加一条记录。 */
    append(record) {
      const chained = chainRecord(tailHash(records, anchor), { ts: new Date().toISOString(), ...record });
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
      return { ...verifyChain(records, anchor), truncated, total };
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
