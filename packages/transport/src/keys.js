/**
 * OpenSSH 密钥编码 —— 免密登录事务的基础。
 *
 * 为什么自己写而不是调用 `ssh-keygen`：
 *   · **ssh2 不接受 Node 的 PKCS8 ed25519 私钥**（实测报 `Unsupported key format`），
 *     所以必须产出 OpenSSH 容器格式；
 *   · 自己实现则**任何机器上都能生成密钥**，不要求本机装 OpenSSH（设计决策 D2）。
 *
 * 正确性由三个独立验证器保证（见 tools/checks/ssh-transport.mjs）：
 *   ① ssh2 的 `utils.parseKey` 能解析我们产出的公钥行与私钥文件；
 *   ② **真实 `ssh-keygen -y -f <私钥>` 导出同一把公钥** ← 由 OpenSSH 自己验证，非自证；
 *   ③ 用它在真实 ssh2 服务端上完成 publickey 认证握手。
 */

import { generateKeyPairSync, createHash, createPublicKey } from 'node:crypto';

/** SSH 线格式的 string：4 字节大端长度 + 内容。 */
function sshString(buf) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

/**
 * ed25519 在 DER 里是定长的：
 *   SPKI   尾部 32 字节 = 原始公钥
 *   PKCS#8 尾部 32 字节 = 私钥种子
 */
function rawEd25519(keyObject, format) {
  const der = keyObject.export({ format: 'der', type: format });
  const raw = der.subarray(der.length - 32);
  if (raw.length !== 32) throw new Error(`ed25519 ${format} 导出的原始密钥长度异常：${raw.length}`);
  return raw;
}

/** 公钥 blob（SSH 线格式）：string "ssh-ed25519" + string pubkey。 */
export function ed25519PublicBlob(publicKey) {
  return Buffer.concat([
    sshString(Buffer.from('ssh-ed25519', 'utf8')),
    sshString(rawEd25519(publicKey, 'spki')),
  ]);
}

/** 生成 OpenSSH 公钥行：`ssh-ed25519 <base64 blob> [comment]`（authorized_keys 里的那一行）。 */
export function opensshPublicKeyLine(publicKey, comment = '') {
  const b64 = ed25519PublicBlob(publicKey).toString('base64');
  return `ssh-ed25519 ${b64}${comment ? ` ${comment}` : ''}`;
}

/**
 * 生成**未加密的 OpenSSH 私钥文件内容**（cipher=none）。
 *
 * 结构（openssh-key-v1）：
 *   magic("openssh-key-v1\0") → ciphername/kdfname/kdfoptions → 密钥数 → 公钥 → 私钥块
 *   私钥块：两个相同 checkint → keytype → pubkey → (seed||pubkey) → comment → 填充(1,2,3…)
 *   填充使整块对齐到 8 字节（cipher=none 的块大小）。
 */
export function opensshPrivateKeyFile(privateKey, publicKey, comment = 'vmprobe') {
  const seed = rawEd25519(privateKey, 'pkcs8');
  const pub = rawEd25519(publicKey, 'spki');
  const pubBlob = ed25519PublicBlob(publicKey);

  // checkint：仅用于检测解密/错配，不需要密码学强度
  const check = Buffer.from(rawEd25519(
    generateKeyPairSync('ed25519').publicKey, 'spki',
  ).subarray(0, 4));

  let priv = Buffer.concat([
    check, check,
    sshString(Buffer.from('ssh-ed25519', 'utf8')),
    sshString(pub),
    sshString(Buffer.concat([seed, pub])),
    sshString(Buffer.from(comment, 'utf8')),
  ]);
  const pad = 8 - (priv.length % 8);
  if (pad !== 8) {
    const padding = Buffer.alloc(pad);
    for (let i = 0; i < pad; i++) padding[i] = i + 1;
    priv = Buffer.concat([priv, padding]);
  }

  const n = Buffer.alloc(4);
  n.writeUInt32BE(1, 0);
  const container = Buffer.concat([
    Buffer.from('openssh-key-v1\0', 'utf8'),
    sshString(Buffer.from('none', 'utf8')),
    sshString(Buffer.from('none', 'utf8')),
    sshString(Buffer.alloc(0)),
    n,
    sshString(pubBlob),
    sshString(priv),
  ]);

  const b64 = container.toString('base64').replace(/(.{70})/g, '$1\n').replace(/\n$/, '');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/**
 * 生成一对专用 ed25519 密钥。
 * @param {string} [comment] 写进公钥行的注释（我们用 `vmprobe:<targetId>:<keyId>` 便于识别与撤销）
 */
export function generateKeypair(comment = '') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey,
    privateKeyPem: opensshPrivateKeyFile(privateKey, publicKey, comment),
    publicKeyLine: opensshPublicKeyLine(publicKey, comment),
  };
}

/**
 * 计算公钥指纹，格式与 OpenSSH 一致：`SHA256:<base64 无填充>`。
 *
 * 这样打印出来的值和 `ssh-keygen -lf` 完全一样，用户能自己核对 ——
 * 主机密钥校验（防 MITM）只有在用户能独立验证时才有意义。
 */
export function publicKeyFingerprint(publicKeyLineOrBlob) {
  let blob;
  if (Buffer.isBuffer(publicKeyLineOrBlob)) {
    blob = publicKeyLineOrBlob;
  } else {
    const parts = String(publicKeyLineOrBlob).trim().split(/\s+/);
    if (parts.length < 2) throw new Error('不是合法的 OpenSSH 公钥行');
    blob = Buffer.from(parts[1], 'base64');
  }
  return `SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`;
}

/** 从 OpenSSH 公钥行取出类型与 blob（用于 authorized_keys 的幂等判定）。 */
export function parsePublicKeyLine(line) {
  const parts = String(line).trim().split(/\s+/);
  if (parts.length < 2) throw new Error('不是合法的 OpenSSH 公钥行');
  return { algo: parts[0], blob: parts[1], comment: parts.slice(2).join(' ') || '' };
}

export { rawEd25519, sshString };
