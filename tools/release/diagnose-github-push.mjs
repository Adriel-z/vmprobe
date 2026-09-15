/**
 * 诊断"GitHub 推不上去"（本机实测过的真实故障，留成工具）。
 *
 * ── 实测结论（2026-09-15）────────────────────────────────────────────────
 *   域名/端口             TCP 443/22      结论
 *   github.com:443        ✖ 连不上        ← **这就是推不上去的原因**
 *   github.com:22         ✔ 通            ← 所以 SSH 推送可行
 *   api.github.com:443    ✔ 通            ← 所以 REST API 可用（备用通道）
 *   codeload/ssh.github.com:443  ✔ 通
 *   DNS 解析正常（20.205.243.166/168，同一网段），hosts 无条目，无系统代理。
 *   ⇒ 不是 DNS 污染，也不是本机配置问题，而是**针对 github.com:443 的连接干扰**。
 *
 * 本脚本按顺序检查：DNS → 端口连通性 → SSH 认证 → 给出结论与下一步建议。
 * **不打印任何私钥内容**（只打印公钥指纹与 GitHub 侧登记的那把 key 的指纹）。
 *
 *   node tools/release/diagnose-github-push.mjs
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import { githubLogin, readTokens } from './verify-tokens.mjs';

const log = (s = '') => console.log(s);
const run = (cmd, args, opts = {}) => {
  try {
    return { ok: true, out: execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim() };
  } catch (err) {
    return { ok: false, out: String(err.stdout ?? '').trim(), err: String(err.stderr ?? err.message).trim() };
  }
};

/** TCP 连接测试（用 node 自己测，避免依赖 PowerShell 的 Test-NetConnection）。 */
async function tcpProbe(host, port, timeoutMs = 8000) {
  const net = await import('node:net');
  return new Promise((resolve) => {
    const sock = net.connect({ host, port });
    const done = (ok, why) => { try { sock.destroy(); } catch { /* 已关闭 */ } resolve({ ok, why }); };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => done(true));
    sock.on('timeout', () => done(false, `超时 ${timeoutMs}ms`));
    sock.on('error', (e) => done(false, e.code ?? e.message));
  });
}

async function dnsA(host) {
  const dns = await import('node:dns/promises');
  try {
    return (await dns.resolve4(host)).join(', ');
  } catch (err) {
    return `解析失败：${err.code ?? err.message}`;
  }
}

log('GitHub 推送链路诊断');
log('='.repeat(60));

// ── 1. DNS ──────────────────────────────────────────────────────────────────
log('\n[1] DNS 解析');
for (const h of ['github.com', 'api.github.com', 'codeload.github.com', 'ssh.github.com']) {
  log(`  ${h.padEnd(22)} → ${await dnsA(h)}`);
}

// ── 2. 端口连通性 ───────────────────────────────────────────────────────────
log('\n[2] 端口连通性（这才是"推不上去"的直接原因）');
const probes = [
  ['github.com', 443, 'git push（HTTPS）走这条'],
  ['github.com', 22, 'git push（SSH）走这条'],
  ['ssh.github.com', 443, 'SSH 备用端口（22 被封时用）'],
  ['api.github.com', 443, 'REST API（备用推送通道）'],
];
const results = [];
for (const [host, port, note] of probes) {
  const r = await tcpProbe(host, port);
  results.push({ host, port, ok: r.ok, why: r.why, note });
  log(`  ${host}:${port}`.padEnd(26) + `${r.ok ? '✔ 通' : `✖ ${r.why}`}`.padEnd(22) + note);
}

// ── 3. 本机代理 ─────────────────────────────────────────────────────────────
log('\n[3] 本机代理（有代理时 git 可以走它）');
let proxy = null;
for (const port of [7890, 7891, 1080, 10809]) {
  const r = await tcpProbe('127.0.0.1', port, 800);
  if (r.ok) { proxy = `http://127.0.0.1:${port}`; break; }
}
log(proxy ? `  探测到 ${proxy}（可用 VMPROBE_GIT_PROXY=${proxy} 指示发布脚本使用）` : '  未探测到本机代理（7890/7891/1080/10809 都没在听）');

// ── 4. SSH 认证 ─────────────────────────────────────────────────────────────
log('\n[4] SSH 认证（github.com:22 通时的首选推送方式）');
const sshDir = join(homedir(), '.ssh');
const privKey = join(sshDir, 'id_ed25519');
const pubKey = `${privKey}.pub`;
log(`  本机私钥 ${privKey}：${existsSync(privKey) ? '存在' : '不存在'}`);
if (existsSync(pubKey)) {
  const fp = run('ssh-keygen', ['-lf', pubKey]);
  log(`  本地公钥指纹：${fp.ok ? fp.out : `读取失败：${fp.err}`}`);
}
let sshAuth = false;
if (existsSync(privKey)) {
  const t = run('ssh', ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-T', 'git@github.com']);
  // 认证成功时 GitHub 返回 "Hi <user>!" 但退出码是 1（不提供 shell）；失败则是 "Permission denied"
  const text = `${t.out}\n${t.err ?? ''}`;
  sshAuth = /Hi [^!]+!/.test(text);
  log(`  ssh -T git@github.com → ${sshAuth ? text.match(/Hi [^!]+!/)[0] : text.split('\n').filter(Boolean).slice(-2).join(' | ')}`);
  if (!sshAuth) {
    // 顺带核对"本机公钥"与"GitHub 上登记的公钥"是否同一把
    try {
      const token = (await readTokens()).github;
      const login = await githubLogin(token);
      const keys = await (await fetch(`https://api.github.com/users/${login}/keys`, {
        headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'vmprobe', Accept: 'application/vnd.github+json' },
      })).json();
      const local = existsSync(pubKey) ? readFileSync(pubKey, 'utf8').trim().split(/\s+/)[1] : null;
      const matched = Array.isArray(keys) && keys.some((k) => k.key.split(/\s+/)[1] === local);
      log(`  本机公钥是否已在 GitHub 账号 ${login} 上登记：${matched ? '是' : '否（这就是认证失败的原因）'}`);
    } catch (err) {
      log(`  （核对公钥时出错：${err.message}）`);
    }
  }
}

// ── 5. 结论 ─────────────────────────────────────────────────────────────────
log('\n[5] 结论与建议');
const https443 = results.find((r) => r.host === 'github.com' && r.port === 443).ok;
const ssh22 = results.find((r) => r.host === 'github.com' && r.port === 22).ok;
const api443 = results.find((r) => r.host === 'api.github.com' && r.port === 443).ok;

if (https443 && !proxy) {
  log('  ✔ github.com:443 正常 —— 直接用 git push 即可。');
} else if (ssh22 && sshAuth) {
  log('  ✔ **首选：用 SSH 推送**（github.com:22 通且认证成功）。');
  log('     发布脚本会自动优先 SSH；也可手动设置远端：');
  log('       git remote set-url origin git@github.com:Adriel-z/vmprobe.git');
} else if (ssh22 && !sshAuth) {
  log('  ⚠ github.com:22 通，但 SSH 认证没成功 —— 需要把本机公钥登记到 GitHub：');
  log('       GitHub → Settings → SSH and GPG keys → New SSH key，粘贴上面的公钥；');
  log('     或用有 admin:public_key 权限的令牌调 API 自动登记（见 README §8.1）。');
} else if (api443) {
  log('  ⚠ 只有 api.github.com 通 —— 用 REST API 备用通道推送：');
  log('       node tools/release/push-via-api.mjs --base <本地提交sha> --apply');
} else {
  log('  ✖ 三条链路都不通 —— 需要代理（VMPROBE_GIT_PROXY=http://127.0.0.1:<port>）或换网络。');
}

log('\n（本诊断只读：不改动任何远端仓库、不打印任何私钥内容）');
