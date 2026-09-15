/**
 * `.vmpz` 归档 —— 跨平台迁移与备份（DESIGN.md §11，M3）。
 *
 * ── 目标 ──────────────────────────────────────────────────────────────────
 * 把一台机器上的 VMProbe 状态**完整搬走**：目标定义、环境画像、日报、加载台账，
 * 可选带上审计链与运行记录。导出的文件应能被另一台 Windows/Linux 上的
 * `vmprobe-archive import` 直接吃下，且**先给出差异预览**再落盘。
 *
 * ── 四条安全纪律（这个功能最容易出事的地方）────────────────────────────────
 *
 * 1. **凭据永不入档**。DSH 的凭据在 `~/.dsh/.credentials.yaml`（本就不在 storageDir 里），
 *    归档只搬 `authRef` **引用名**；私钥（`keys/`）默认也不进档。
 * 2. **审计密钥永不入档**。`audit-hmac.key` 是"抗伪造"的根，它一旦随归档流出去，
 *    任何人拿到归档都能伪造那份审计链 —— 那就等于把 HMAC 白做了。
 *    这里**硬编码排除**（不是"默认不选"，是根本没有入选路径），并有测试盯着。
 * 3. **`--include-secrets` 必须加密**。带私钥的归档用 scrypt 派生密钥 + AES-256-GCM 加密，
 *    口令从交互式输入读（不回显）。**不允许**"带秘密但不加密"这种组合存在。
 * 4. **导入前必须能预览差异**。默认 `--dry-run`，给出 新增/冲突/覆盖/需重录凭据 四类结论。
 *
 * ── schema 版本 ───────────────────────────────────────────────────────────
 * 归档里带 `schema: 'vmprobe/archive/1'`。导入时：
 *   · 主版本相同 → 正常导入；
 *   · 主版本更高 → **拒绝**（旧程序读新格式只会误解，不该"尽力而为"）；
 *   · 主版本更低 → 走迁移函数（当前只有 v1，因此直接报"无需迁移/不支持"）。
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, relative, sep } from 'node:path';

import { sha256Hex } from './audit.js';
import { zipCreate, zipRead } from './zip.js';

/** 归档 schema 版本。 */
export const ARCHIVE_SCHEMA = 'vmprobe/archive/1';

/** 归档内的固定成员名。 */
export const MANIFEST_NAME = 'manifest.json';
export const SECRETS_NAME = 'secrets.enc.json';

/**
 * **永不入档**的文件名（硬编码，无开关）。
 * 命中的条目在收集阶段就被跳过，并在清单里如实记下"跳过了什么、为什么"。
 */
export const NEVER_ARCHIVE = [
  'audit-hmac.key',            // 密钥一旦流出，HMAC 保护归零
  '.credentials.yaml',         // DSH 凭据（正常不在 storageDir 内，这里防手滑）
  '.git-credentials',
];

/** 需要 `--include-secrets` 才进去的路径前缀（私钥等）。 */
export const SECRET_PATHS = ['keys/'];

/** 默认导出内容（按前缀）。 */
const DEFAULT_INCLUDE = ['targets.json', 'facts/', 'reports/', 'loads.jsonl'];
/** 需显式开关的附加内容（体积大 / 敏感度更高）。 */
const OPTIONAL_INCLUDE = { audit: ['logs/'], runs: ['runs/'] };

/** 脱敏档位。 */
export const REDACTION_LEVELS = ['none', 'minimal', 'standard'];

/**
 * 把一个值按档位脱敏（只处理"能识别出是内网/主机标识"的字段）。
 * `none` 原样；`minimal` 打码 IPv4 与主机名；`standard` 额外把标签清空。
 */
export function redactValue(key, value, level = 'standard') {
  if (level === 'none') return value;
  if (typeof value === 'string') {
    if (key === 'hostname' || key === 'label') {
      // 保留可辨识的前缀，但把标识打掉：10.0.0.5 → 10.0.*.*，vm-prod-01 → vm-***
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
        const parts = value.split('.');
        return `${parts[0]}.${parts[1]}.*.*`;
      }
      return value.replace(/[A-Za-z0-9-]{2,}$/, '***');
    }
  }
  if (level === 'standard' && key === 'tags' && Array.isArray(value)) return [];
  return value;
}

/** 归一化成 zip 里使用的正斜杠相对路径。 */
export function toArchivePath(absPath, root) {
  return relative(root, absPath).split(sep).join('/');
}

/** 列出 root 下的全部文件（相对路径 → 绝对路径），跳过 NEVER_ARCHIVE。 */
function walk(root) {
  const out = [];
  const walkDir = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;                       // 目录不存在：跳过（首次使用时很正常）
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) { walkDir(full); continue; }
      if (!entry.isFile()) continue;
      out.push(full);
    }
  };
  walkDir(root);
  return out;
}

/**
 * 收集要入档的条目。
 *
 * @param {object} o
 * @param {string} o.dir storageDir
 * @param {boolean} [o.includeAudit] 是否带审计链（logs/）
 * @param {boolean} [o.includeRuns] 是否带运行记录（runs/）
 * @param {boolean} [o.includeSecrets] 是否带私钥（**必须**配合加密，见下）
 * @param {string} [o.redaction] 脱敏档位
 * @param {number} [o.nowMs] 便于测试固定时间
 */
export function collectEntries({ dir, includeAudit = false, includeRuns = false, includeSecrets = false, redaction = 'standard' } = {}) {
  if (!existsSync(dir)) throw new Error(`storageDir 不存在：${dir}`);
  const prefixes = [
    ...DEFAULT_INCLUDE,
    ...(includeAudit ? OPTIONAL_INCLUDE.audit : []),
    ...(includeRuns ? OPTIONAL_INCLUDE.runs : []),
    ...(includeSecrets ? SECRET_PATHS : []),
  ];

  const skipped = [];
  const selected = [];
  for (const full of walk(dir)) {
    const rel = toArchivePath(full, dir);
    const base = posix.basename(rel);

    if (NEVER_ARCHIVE.includes(base)) {
      skipped.push({ path: rel, reason: '永不入档（密钥/凭据类）' });
      continue;
    }
    const isSecret = SECRET_PATHS.some((p) => rel.startsWith(p));
    if (isSecret && !includeSecrets) {
      skipped.push({ path: rel, reason: '属于私钥（需 --include-secrets 且必须加密）' });
      continue;
    }
    if (isSecret && includeSecrets) { selected.push({ full, rel, secret: true }); continue; }

    if (!prefixes.some((p) => rel === p || rel.startsWith(p))) {
      skipped.push({ path: rel, reason: '不在本次导出范围（可用 --include-audit / --include-runs 调整）' });
      continue;
    }
    selected.push({ full, rel, secret: false });
  }

  const entries = selected.map(({ full, rel, secret }) => {
    let data = readFileSync(full);
    // 目标定义在导出时按档位脱敏（IP/主机名打码），并从清单里如实标注
    if (!secret && rel === 'targets.json' && redaction !== 'none') {
      data = Buffer.from(redactTargetsFile(data, redaction), 'utf8');
    }
    return { name: `data/${rel}`, data, rel, secret, bytes: data.length };
  });

  return { entries, skipped };
}

/** 对 targets.json 做脱敏（保留结构，只打码标识字段）。 */
function redactTargetsFile(buf, level) {
  try {
    const doc = JSON.parse(buf.toString('utf8'));
    const targets = Array.isArray(doc) ? doc : (doc.targets ?? []);
    const next = targets.map((t) => {
      const copy = { ...t };
      for (const key of ['hostname', 'label']) {
        if (typeof copy[key] === 'string') copy[key] = redactValue(key, copy[key], level);
      }
      if (Array.isArray(copy.tags)) copy.tags = redactValue('tags', copy.tags, level);
      return copy;
    });
    const outDoc = Array.isArray(doc) ? next : { ...doc, targets: next };
    return `${JSON.stringify(outDoc, null, 2)}\n`;
  } catch {
    // 解析不了就原样带走（宁可留着内容，也不要因为脱敏失败丢文件）
    return buf.toString('utf8');
  }
}

/** scrypt 参数（够硬，且导出/导入耗时在百毫秒级）。 */
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

/** 用口令加密一段 JSON（AES-256-GCM）。 */
export function encryptSecrets(plaintext, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 8) {
    throw new Error('口令至少 8 个字符（否则 scrypt 的意义就不大了）');
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return {
    algo: 'aes-256-gcm',
    kdf: { name: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64') },
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: enc.toString('base64'),
  };
}

/** 解密密文；口令错误会抛错（GCM 认证失败），**不会**返回垃圾数据。 */
export function decryptSecrets(doc, passphrase) {
  if (!doc || doc.algo !== 'aes-256-gcm') throw new Error(`不支持的加密格式：${JSON.stringify(doc?.algo)}`);
  const salt = Buffer.from(doc.kdf.salt, 'base64');
  const key = scryptSync(passphrase, salt, SCRYPT.keylen, { N: doc.kdf.N, r: doc.kdf.r, p: doc.kdf.p });
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(doc.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(doc.tag, 'base64'));
  try {
    return Buffer.concat([
      decipher.update(Buffer.from(doc.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    // 不要泄露"是长度不对还是校验失败"这类细节，也不要返回半截明文
    throw new Error('解密失败：口令不对，或归档内容被改动过（GCM 认证未通过）');
  }
}

/**
 * 导出一个归档。
 *
 * @returns {{buffer: Buffer, manifest: object}}
 */
export function exportArchive({
  dir, version = '0.0.0', includeAudit = false, includeRuns = false,
  includeSecrets = false, redaction = 'standard', passphrase = null,
  now = new Date(), platform = process.platform, hostname = null,
} = {}) {
  if (includeSecrets && !passphrase) {
    throw new Error('--include-secrets 必须同时提供口令：带秘密的归档**不允许**不加密（见 DESIGN §11）');
  }
  if (!REDACTION_LEVELS.includes(redaction)) {
    throw new Error(`未知的脱敏档位 ${JSON.stringify(redaction)}（可选：${REDACTION_LEVELS.join(' / ')}）`);
  }
  const { entries, skipped } = collectEntries({ dir, includeAudit, includeRuns, includeSecrets, redaction });

  const zipEntries = entries.map((e) => ({ name: e.name, data: e.data }));
  const secretsEntry = entries.find((e) => e.name === `data/${SECRETS_NAME}`);
  const hasSecrets = entries.some((e) => e.secret);

  // 秘密部分整体加密成一个额外条目（而不是逐文件加密），这样"有没有秘密"一目了然
  if (hasSecrets) {
    const secretFiles = entries.filter((e) => e.secret).map((e) => ({
      path: e.rel, bytes: e.bytes, base64: e.data.toString('base64'), sha256: sha256Hex(e.data.toString('base64')),
    }));
    const enc = encryptSecrets(JSON.stringify({ schema: 'vmprobe/secrets/1', files: secretFiles }), passphrase);
    zipEntries.push({ name: SECRETS_NAME, data: Buffer.from(JSON.stringify(enc, null, 2), 'utf8') });
    // 私钥**不再以明文形式**出现在 zip 里
    for (let i = zipEntries.length - 1; i >= 0; i -= 1) {
      if (zipEntries[i].name.startsWith('data/keys/')) zipEntries.splice(i, 1);
    }
  }

  const manifest = {
    schema: ARCHIVE_SCHEMA,
    createdAt: now.toISOString(),
    producer: { name: 'vmprobe', version, platform: hostname ? `${platform}/${hostname}` : platform },
    redaction,
    includes: {
      audit: Boolean(includeAudit),
      runs: Boolean(includeRuns),
      secrets: hasSecrets,
      secretsEncrypted: hasSecrets ? 'aes-256-gcm/scrypt' : null,
    },
    counts: { files: entries.length, secretFiles: entries.filter((e) => e.secret).length, skipped: skipped.length },
    entries: entries.filter((e) => !e.secret).map((e) => ({ path: e.rel, bytes: e.bytes, sha256: sha256Hex(e.data.toString('base64')) })),
    // 跳过了什么、为什么 —— 归档要能自证它**没有**带走什么
    skipped,
  };
  zipEntries.unshift({ name: MANIFEST_NAME, data: Buffer.from(JSON.stringify(manifest, null, 2), 'utf8') });

  return { buffer: zipCreate(zipEntries), manifest };
}

/**
 * 读取并**校验**一个归档：schema 版本、清单 → 条目一一对应、逐条 sha256。
 * 任何不符都抛错 —— 归档是迁移的载体，"尽力而为地导入半个"比拒绝更危险。
 *
 * @param {Buffer} buf
 * @param {{passphrase?: string, targetSchema?: string}} [opts]
 */
export function readArchive(buf, opts = {}) {
  const raw = zipRead(buf);
  const byName = new Map(raw.map((e) => [e.name, e]));
  for (const e of raw) {
    if (!e.crcOk) throw new Error(`归档条目 CRC 不符：${e.name}（文件可能损坏）`);
  }

  const manifestEntry = byName.get(MANIFEST_NAME);
  if (!manifestEntry) throw new Error(`归档里没有 ${MANIFEST_NAME} —— 不是 VMProbe 归档`);
  let manifest;
  try {
    manifest = JSON.parse(manifestEntry.data.toString('utf8'));
  } catch (err) {
    throw new Error(`${MANIFEST_NAME} 不是合法 JSON：${err.message}`);
  }

  const wantSchema = opts.targetSchema ?? ARCHIVE_SCHEMA;
  if (manifest.schema !== wantSchema) {
    // ⚠️ 版本号在**最后一段**（`vmprobe/archive/1` → 1）。
    //    第一版写成 `split('/')[1]`，取到的是 `archive` → NaN，
    //    于是 `NaN > NaN` 恒 false，"更高版本"会掉进"没有迁移路径"这个分支 ——
    //    报错信息虽然仍是否决，但**理由说错了**，而理由正是运维判断的依据。
    const major = (s) => Number(String(s).split('/').pop());
    const mine = major(wantSchema);
    const theirs = major(manifest.schema);
    if (Number.isFinite(theirs) && Number.isFinite(mine) && theirs > mine) {
      throw new Error(
        `归档 schema ${manifest.schema} 比本程序支持的 ${wantSchema} 更新 —— 拒绝导入。`
        + '旧程序读新格式只会误解内容，升级 VMProbe 后再导。',
      );
    }
    throw new Error(
      `归档 schema ${manifest.schema} 与支持的 ${wantSchema} 不同，且没有可用的迁移路径（当前只有 v1）。`,
    );
  }

  const files = new Map();
  for (const meta of manifest.entries) {
    const entry = byName.get(`data/${meta.path}`);
    if (!entry) throw new Error(`清单声明了 ${meta.path}，但归档里没有该条目`);
    const digest = sha256Hex(entry.data.toString('base64'));
    if (digest !== meta.sha256) {
      throw new Error(`归档条目内容与清单不符：${meta.path}（期望 ${meta.sha256.slice(0, 12)}…，实际 ${digest.slice(0, 12)}…）`);
    }
    if (entry.data.length !== meta.bytes) {
      throw new Error(`归档条目长度与清单不符：${meta.path}`);
    }
    files.set(meta.path, entry.data);
  }

  let secrets = null;
  const secretsEntry = byName.get(SECRETS_NAME);
  if (secretsEntry) {
    if (!opts.passphrase) throw new Error('该归档包含加密的私钥内容，导入时必须提供口令');
    const doc = JSON.parse(secretsEntry.data.toString('utf8'));
    const plain = JSON.parse(decryptSecrets(doc, opts.passphrase));
    secrets = new Map(plain.files.map((f) => [f.path, Buffer.from(f.base64, 'base64')]));
  }

  // 清单声明的"跳过项"必须能在归档里得到印证：被跳过的内容**不能**同时存在
  for (const s of manifest.skipped ?? []) {
    if (files.has(s.path) || secrets?.has(s.path)) {
      throw new Error(`清单说跳过了 ${s.path}，但归档里却有它 —— 清单与内容矛盾，拒绝导入`);
    }
  }

  return { manifest, files, secrets };
}

/**
 * 与本地现状做差异预览（导入前给人看的那张表）。
 *
 * 四类结论：
 *   · `added`     本地没有 → 会新增
 *   · `identical` 内容一致 → 无动作
 *   · `conflict`  本地有且不同 → 默认**不覆盖**，需 `--overwrite` 明确同意
 *   · `credentialGaps` 归档里的目标引用了本地没有的凭据 → 导入后需重新录入
 */
export function diffArchive({ archive, dir, existingCredentials = null }) {
  const added = [];
  const identical = [];
  const conflict = [];

  for (const [rel, data] of archive.files) {
    const target = join(dir, rel.split('/').join(sep));
    const digest = sha256Hex(data.toString('base64'));
    if (!existsSync(target)) { added.push({ path: rel, bytes: data.length, sha256: digest }); continue; }
    const local = readFileSync(target);
    const localDigest = sha256Hex(local.toString('base64'));
    if (localDigest === digest) identical.push({ path: rel, bytes: data.length });
    else conflict.push({ path: rel, bytes: data.length, sha256: digest, localSha256: localDigest, localBytes: statSync(target).size });
  }

  // 凭据缺口：目标定义里的 authRef 在本地是否存在
  const credentialGaps = [];
  const targetsBuf = archive.files.get('targets.json');
  if (targetsBuf) {
    try {
      const doc = JSON.parse(targetsBuf.toString('utf8'));
      const targets = Array.isArray(doc) ? doc : (doc.targets ?? []);
      for (const t of targets) {
        const ref = t?.authRef?.ref ?? t?.authRef;
        if (typeof ref !== 'string') continue;
        if (Array.isArray(existingCredentials)) {
          if (!existingCredentials.includes(ref)) credentialGaps.push({ targetId: t.id, ref });
        } else {
          credentialGaps.push({ targetId: t.id, ref, unknown: true });
        }
      }
    } catch { /* 目标文件坏了不该让预览失败 */ }
  }

  return {
    added,
    identical,
    conflict,
    credentialGaps,
    secrets: archive.secrets ? [...archive.secrets.keys()] : [],
  };
}

/**
 * 应用导入。**先备份**再写（冲突文件写 `.vmpz-bak`），全部原子写。
 *
 * @returns {{written: string[], backedUp: string[], skipped: string[], secretsWritten: string[]}}
 */
export function applyImport({ archive, dir, overwrite = false, now = new Date() }) {
  const written = [];
  const backedUp = [];
  const skipped = [];

  for (const [rel, data] of archive.files) {
    const target = join(dir, rel.split('/').join(sep));
    if (existsSync(target)) {
      const local = readFileSync(target);
      if (sha256Hex(local.toString('base64')) === sha256Hex(data.toString('base64'))) {
        skipped.push(rel);
        continue;
      }
      if (!overwrite) {
        skipped.push(`${rel}（本地已存在且不同，未加 --overwrite）`);
        continue;
      }
      const backup = `${target}.vmpz-bak`;
      writeFileSync(backup, local);
      backedUp.push(backup);
    }
    mkdirSync(dirname(target), { recursive: true });
    const tmp = `${target}.vmpz-tmp-${process.pid}`;
    writeFileSync(tmp, data, { mode: 0o600 });
    renameSync(tmp, target);
    written.push(rel);
  }

  // 私钥：只在解密成功时写入，且**强制 0600**
  const secretsWritten = [];
  if (archive.secrets) {
    for (const [rel, data] of archive.secrets) {
      const target = join(dir, rel.split('/').join(sep));
      mkdirSync(dirname(target), { recursive: true });
      const tmp = `${target}.vmpz-tmp-${process.pid}`;
      writeFileSync(tmp, data, { mode: 0o600 });
      renameSync(tmp, target);
      secretsWritten.push(rel);
    }
  }

  return { written, backedUp, skipped, secretsWritten, at: now.toISOString() };
}

export { timingSafeEqual };
