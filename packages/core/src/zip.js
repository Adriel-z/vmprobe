/**
 * 最小 ZIP 读写（无第三方依赖）。
 *
 * ── 为什么自己写 ──────────────────────────────────────────────────────────
 * 归档格式要能被**别的工具**打开（用户手上可能是 Windows 的资源管理器、`unzip`、
 * 或另一台机器上的 DSH），所以不能用"自定义 tar"糊过去。而 zip 需要压缩库，
 * 本项目又不该为了一个导出功能引入依赖树 —— 于是直接用 Node 自带的 `zlib`
 * （deflate/inflate 都在里面），自己拼 ZIP 容器。
 *
 * ── 支持的范围（够用即可，越界**明确报错**而不是静默降级）──────────────────
 *   · 写：stored（不压缩，适合已压缩内容）与 deflate；UTF-8 文件名（置 EFS 标志位）
 *   · 读：stored 与 deflate；**拒绝**其它压缩方法（zip64 / 加密 zip / bzip2…），
 *     报错里说明是哪一种 —— 静默当成"空文件"是最糟的处理方式
 *   · **不做 zip64**：条目数与单文件都受 32 位限制（4 GiB），超出即报错
 *
 * ── 正确性要件 ────────────────────────────────────────────────────────────
 *   · 每条要 CRC32（解压方靠它判断内容完整）；
 *   · 中央目录里的 `local header offset` 必须准（否则解压器找不到数据）；
 *   · 解码时按 `compressedSize` 精确截取，不能靠"读到下一个 header"——
 *     后者在数据里恰好出现 PK 魔数时会读歪。
 *
 * 该实现已用**外部工具交叉验证**：导出的 `.vmpz` 能被 PowerShell 的
 * `Expand-Archive` 正常解开（见 `tools/checks/check-archive.mjs`）。
 */

import { deflateRawSync, inflateRawSync } from 'node:zlib';

const LOCAL_SIG = 0x04034b50;
const CENTRAL_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;

/** 压缩方法。 */
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[i] = c;
  }
  return table;
})();

/** CRC32（ZIP 用的标准多项式）。 */
export function crc32(buf) {
  let crc = -1;
  for (let i = 0; i < buf.length; i += 1) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ -1) >>> 0;
}

export class ZipError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ZipError';
    this.code = 'zip_error';
  }
}

/**
 * 打包成 zip。
 * @param {{name: string, data: Buffer|string, compress?: boolean}[]} entries
 * @param {{level?: number}} [options]
 * @returns {Buffer}
 */
export function zipCreate(entries, options = {}) {
  const level = Number.isInteger(options.level) ? options.level : 9;
  const chunks = [];
  const central = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    if (!nameBuf.length) throw new ZipError('zip 条目名不能为空');
    if (nameBuf.length > 0xffff) throw new ZipError(`条目名过长：${entry.name}`);
    const raw = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(String(entry.data), 'utf8');
    if (raw.length > 0xffffffff) throw new ZipError(`条目过大（不做 zip64）：${entry.name}`);

    const crc = crc32(raw);
    // 小文件压缩收益低但开销固定，因此"是否压缩"由调用方按内容类型决定；
    // 这里额外做一次"压不小就不压"的判断，避免把已压缩内容再膨胀一遍。
    let method = METHOD_STORED;
    let payload = raw;
    if (entry.compress !== false) {
      const deflated = deflateRawSync(raw, { level });
      if (deflated.length < raw.length) {
        method = METHOD_DEFLATE;
        payload = deflated;
      }
    }

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(LOCAL_SIG, 0);
    localHeader.writeUInt16LE(20, 4);            // version needed
    localHeader.writeUInt16LE(0x0800, 6);        // 标志位：文件名是 UTF-8（EFS）
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(0, 10);            // 修改时间（保持 0 → 归档可复现）
    localHeader.writeUInt16LE(0, 12);            // 修改日期
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(payload.length, 18);
    localHeader.writeUInt32LE(raw.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);            // extra length

    chunks.push(localHeader, nameBuf, payload);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(CENTRAL_SIG, 0);
    centralHeader.writeUInt16LE(20, 4);          // version made by
    centralHeader.writeUInt16LE(20, 6);          // version needed
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(payload.length, 20);
    centralHeader.writeUInt32LE(raw.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);          // extra
    centralHeader.writeUInt16LE(0, 32);          // comment
    centralHeader.writeUInt16LE(0, 34);          // disk number
    centralHeader.writeUInt16LE(0, 36);          // internal attrs
    centralHeader.writeUInt32LE(0, 38);          // external attrs
    centralHeader.writeUInt32LE(offset, 42);     // local header offset
    central.push(centralHeader, nameBuf);

    offset += localHeader.length + nameBuf.length + payload.length;
  }

  const centralBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIG, 0);
  eocd.writeUInt16LE(0, 4);                      // 本磁盘号
  eocd.writeUInt16LE(0, 6);                      // 中央目录起始磁盘
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);                     // 注释长度

  return Buffer.concat([...chunks, centralBuf, eocd]);
}

/**
 * 解开 zip。返回 `{name, data, size, crcOk}` 列表。
 * @param {Buffer} buf
 */
export function zipRead(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 22) throw new ZipError('不是有效的 zip（长度不足）');

  // 从尾部找 EOCD（允许最多 64KiB 注释）
  let eocd = -1;
  const minEocd = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= minEocd; i -= 1) {
    if (buf.readUInt32LE(i) === EOCD_SIG) { eocd = i; break; }
  }
  if (eocd === -1) throw new ZipError('找不到 zip 中央目录（EOCD）—— 文件可能被截断或不是 zip');

  const count = buf.readUInt16LE(eocd + 10);
  const centralSize = buf.readUInt32LE(eocd + 12);
  const centralOffset = buf.readUInt32LE(eocd + 16);
  if (centralOffset + centralSize > buf.length) {
    throw new ZipError('中央目录越界 —— 文件被截断');
  }

  const out = [];
  let p = centralOffset;
  for (let i = 0; i < count; i += 1) {
    if (buf.readUInt32LE(p) !== CENTRAL_SIG) throw new ZipError(`第 ${i} 条中央目录记录签名不对`);
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compSize = buf.readUInt32LE(p + 20);
    const rawSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    p += 46 + nameLen + extraLen + commentLen;

    if (buf.readUInt32LE(localOffset) !== LOCAL_SIG) {
      throw new ZipError(`条目 ${name} 的本地头签名不对`);
    }
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const payload = buf.subarray(dataStart, dataStart + compSize);

    let data;
    if (method === METHOD_STORED) data = Buffer.from(payload);
    else if (method === METHOD_DEFLATE) {
      try {
        data = inflateRawSync(payload);
      } catch (err) {
        throw new ZipError(`条目 ${name} 解压失败：${err.message}`);
      }
    } else {
      // 静默当成空文件是最糟的处理方式 —— 明确说是哪种不支持
      throw new ZipError(
        `条目 ${name} 使用了不支持的压缩方法 ${method}`
        + '（本实现只支持 stored=0 与 deflate=8；zip64 与加密 zip 会落到这里）',
      );
    }

    if (data.length !== rawSize) {
      throw new ZipError(`条目 ${name} 长度不符：期望 ${rawSize}，实际 ${data.length}`);
    }
    const actualCrc = crc32(data);
    out.push({ name, data, size: data.length, crcOk: actualCrc === crc, expectedCrc: crc, actualCrc });
  }
  return out;
}

/** 从 zip 里取一个条目（找不到返回 null）。 */
export function zipEntry(buf, name) {
  return zipRead(buf).find((e) => e.name === name) ?? null;
}

export { METHOD_DEFLATE, METHOD_STORED };
