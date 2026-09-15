/**
 * 走 **GitHub REST API** 推送（git-over-HTTPS 被墙时的备用通道）。
 *
 * ── 为什么需要它 ──────────────────────────────────────────────────────────
 * 这台机器上 `github.com:443`（git push 用的）**时通时不通**，实测发布 v0.3.0 时
 * 三次重试全部 21 秒超时（"Could not connect to server" / "Empty reply from server"）；
 * 而 **`api.github.com` 一直可达**。两者是不同的域名与链路，于是就有了这条备用通道。
 *
 * ── 它怎么工作 ────────────────────────────────────────────────────────────
 * Git Data API 可以逐块构造提交：上传 blob → 建 tree（可基于父 tree 增量）→ 建 commit →
 * 更新 ref。因此可以**完整复刻本地提交**（包括每个提交的消息与父子关系），
 * 而不是"压成一个提交糊上去"。
 *
 *   node tools/release/push-via-api.mjs                # 预演：列出将推送的提交
 *   node tools/release/push-via-api.mjs --apply         # 真正推送 main 与 v* tag
 *
 * ── 三个注意点 ────────────────────────────────────────────────────────────
 *   ① 令牌只进请求头，**绝不打印、绝不落盘**；
 *   ② 只做**快进**（远端 ref 必须是本地历史的祖先），否则拒绝 —— 这是"备用通道"，
 *      不该悄悄把远端历史改掉；
 *   ③ 二进制安全：blob 用 base64 传输，不经过任何文本编码转换。
 */

import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { githubLogin, readTokens } from './verify-tokens.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const REPO = 'vmprobe';
const apply = process.argv.includes('--apply');

const log = (s = '') => console.log(s);
const step = (s) => console.log(`\n▶ ${s}`);
const git = (args, opts = {}) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', ...opts });
/** 取二进制内容（blob）——**不要**用 utf8 编码读，那会破坏二进制文件。 */
const gitBlob = (spec) => execFileSync('git', ['cat-file', 'blob', spec], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 });

const token = (await readTokens()).github;
if (!token) throw new Error('没有 GITHUB_TOKEN，无法走 API 推送');
const login = await githubLogin(token);
const API = `https://api.github.com/repos/${login}/${REPO}`;
const headers = {
  Authorization: `Bearer ${token}`,
  'User-Agent': 'vmprobe-release',
  Accept: 'application/vnd.github+json',
  'Content-Type': 'application/json',
};

async function api(path, init = {}) {
  const res = await fetch(`${API}${path}`, { ...init, headers });
  if (!res.ok && res.status !== 404) {
    throw new Error(`${init.method ?? 'GET'} ${path} → HTTP ${res.status} ${await res.text()}`);
  }
  return res.status === 404 ? null : res.json();
}

step('对比本地与远端');
const localHead = git(['rev-parse', 'HEAD']).trim();
const remoteRef = await api('/git/ref/heads/main');
if (!remoteRef) throw new Error('远端没有 main 分支（请先用普通 git push 建立）');
const remoteSha = remoteRef.object.sha;

/**
 * 远端提交在本地**不一定存在** —— 本通道自己创建的提交就是这种情况
 * （它由 API 生成，本地 never fetch 过；而 git-over-HTTPS 正是被墙的那条链路）。
 *
 * 因此：远端 sha 本地已知时直接用它；未知时必须由调用方用 `--base <本地sha>`
 * **明确指出"远端 HEAD 对应哪个本地提交"** —— 这个判断只能由人来做，
 * 脚本不猜（猜错会导致重复提交或漏提交）。
 */
const baseIdx = process.argv.indexOf('--base');
const baseArg = baseIdx !== -1 ? process.argv[baseIdx + 1] : null;
let baseSha = remoteSha;
let baseIsLocal = true;
try {
  git(['cat-file', '-e', `${remoteSha}^{commit}`]);
} catch {
  baseIsLocal = false;
}
if (!baseIsLocal) {
  if (!baseArg) {
    throw new Error(
      `远端 main 指向 ${remoteSha.slice(0, 7)}，但这个提交在本地不存在（它可能是本通道创建的）。\n`
      + '  请用 --base <本地提交sha> 说明"远端 HEAD 对应本地的哪个提交"，例如：\n'
      + `    node tools/release/push-via-api.mjs --base ${localHead.slice(0, 7)} --apply`,
    );
  }
  git(['cat-file', '-e', `${baseArg}^{commit}`]);
  baseSha = git(['rev-parse', baseArg]).trim();
  log(`  ⚠ 远端 ${remoteSha.slice(0, 7)} 本地不存在；按 --base 视为本地 ${baseSha.slice(0, 7)}`);
  log('    （这一断言由你负责：它必须真的与远端内容一致，否则会产生重复提交）');
}

log(`  本地 HEAD : ${localHead.slice(0, 7)} ${git(['log', '-1', '--format=%s', localHead]).trim()}`);
log(`  远端 main : ${remoteSha.slice(0, 7)}（基线 ${baseSha.slice(0, 7)}）`);

if (localHead === baseSha) {
  log('\n  已一致，无需推送。');
  process.exit(0);
}

// ③ 只做快进：基线必须是本地的祖先
let ancestor = false;
try {
  git(['merge-base', '--is-ancestor', baseSha, localHead]);
  ancestor = true;
} catch { ancestor = false; }
if (!ancestor) {
  throw new Error(
    `基线 ${baseSha.slice(0, 7)} 不是本地历史的祖先 —— 拒绝用 API 通道改写远端历史。\n`
    + '  这种情况请先人工确认分支状态（本通道只做快进）。',
  );
}

const commits = git(['rev-list', '--reverse', `${baseSha}..${localHead}`]).trim().split('\n').filter(Boolean);
log(`  待推送 ${commits.length} 个提交：`);
for (const c of commits) log(`    ${c.slice(0, 7)} ${git(['log', '-1', '--format=%s', c]).trim()}`);

const tags = git(['tag', '--points-at', localHead]).trim().split('\n').filter(Boolean)
  .concat(git(['tag', '-l', 'v*']).trim().split('\n').filter(Boolean))
  .filter((v, i, a) => v && a.indexOf(v) === i);
log(`  本地 tag：${tags.join('、') || '（无）'}`);

if (!apply) {
  log('\n（预演：未改动远端。加 --apply 执行）');
  process.exit(0);
}

step('逐提交上传（blob → tree → commit）');
let parentSha = remoteSha;
let parentTree = (await api(`/git/commits/${remoteSha}`)).tree.sha;
/**
 * 本地提交 sha → 远端新提交 sha。
 *
 * ⚠️ 第一版偷懒：tag 一律指向"最后推上去的那个提交"。结果是 **v0.3.0 指向了它之后的
 * 一个提交**（本机 877f7f5），而 Gitee 上同一个 tag 指向的是 9b01ecd ——
 * 两个平台同一个 tag 指向不同提交，正是"跨平台发布"最不该出现的那种不一致。
 * 所以老老实实建映射：tag 指向它**自己那个目标提交**映射后的 sha。
 */
const shaMap = new Map([[baseSha, remoteSha]]);   // 基线本地 sha → 远端真实 sha

for (const sha of commits) {
  const message = git(['log', '-1', '--format=%B', sha]).replace(/\n+$/, '\n');
  const parents = git(['rev-list', '--parents', '-n', '1', sha]).trim().split(/\s+/).slice(1);
  // 用**该提交自己的父提交**做 diff（而不是上一个已推提交），这样 merge/空提交也不会读歪
  const status = git(['diff', '--name-status', `${parents[0]}`, sha]).trim().split('\n').filter(Boolean);

  const treeEntries = [];
  for (const line of status) {
    const [code, ...rest] = line.split('\t');
    const path = rest.join('\t');
    if (code.startsWith('D')) {
      treeEntries.push({ path, mode: '100644', type: 'blob', sha: null });   // 删除
      continue;
    }
    const content = gitBlob(`${sha}:${path}`);
    const blob = await api('/git/blobs', {
      method: 'POST',
      body: JSON.stringify({ content: content.toString('base64'), encoding: 'base64' }),
    });
    const mode = git(['ls-tree', sha, '--', path]).trim().split(/\s+/)[0] || '100644';
    treeEntries.push({ path, mode, type: 'blob', sha: blob.sha });
  }

  const tree = treeEntries.length
    ? await api('/git/trees', { method: 'POST', body: JSON.stringify({ base_tree: parentTree, tree: treeEntries }) })
    : { sha: parentTree };

  const commit = await api('/git/commits', {
    method: 'POST',
    body: JSON.stringify({ message, tree: tree.sha, parents: [parentSha] }),
  });
  log(`  ✔ ${sha.slice(0, 7)} → ${commit.sha.slice(0, 7)}（${treeEntries.length} 个文件变更）${git(['log', '-1', '--format=%s', sha]).trim()}`);
  shaMap.set(sha, commit.sha);
  parentSha = commit.sha;
  parentTree = tree.sha;
}

step('更新 ref 与 tag');
await api('/git/refs/heads/main', { method: 'PATCH', body: JSON.stringify({ sha: parentSha, force: false }) });
log(`  main → ${parentSha.slice(0, 7)}`);

for (const t of tags) {
  // ⚠️ 注意 `^{commit}`：不加它拿到的是**tag 对象**的 sha（annotated tag），
  //    推到远端会变成一个指向 tag 对象的 tag，语义不对。
  const target = git(['rev-list', '-n', '1', t]).trim();
  const mapped = shaMap.get(target);
  if (!mapped) {
    log(`  tag ${t} → 目标 ${target.slice(0, 7)} 不在本次推送范围内（远端可能已有，跳过）`);
    continue;
  }
  const existing = await api(`/git/ref/tags/${t}`);
  if (existing && existing.object.sha === mapped) {
    log(`  tag ${t} 已存在且指向正确（${mapped.slice(0, 7)}）`);
    continue;
  }
  if (existing) {
    // 已存在但指向别处：**强制改到正确目标**（这正是"两平台 tag 不一致"的修法）
    await api(`/git/refs/tags/${t}`, {
      method: 'PATCH',
      body: JSON.stringify({ sha: mapped, force: true }),
    });
    log(`  tag ${t} 已修正 → ${mapped.slice(0, 7)}（原先指向 ${existing.object.sha.slice(0, 7)}）`);
    continue;
  }
  await api('/git/refs', { method: 'POST', body: JSON.stringify({ ref: `refs/tags/${t}`, sha: mapped }) });
  log(`  tag ${t} → ${mapped.slice(0, 7)}`);
}

log('\n✔ 已通过 API 推送完成（可用 tools/release/publish.mjs --apply 补发 release，或直接 verify-published 核对）');
