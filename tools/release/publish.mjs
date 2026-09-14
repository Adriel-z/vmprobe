/**
 * 发布：创建远端仓库（若不存在）→ 推送 → 发布 release（GitHub + Gitee 同步）。
 *
 * 用法：
 *   node tools/release/publish.mjs                  # 预演（只检查，不改动远端）
 *   node tools/release/publish.mjs --apply           # 真正执行
 *   node tools/release/publish.mjs --apply --tag v0.2.0
 *
 * ── 令牌处理（三条纪律）────────────────────────────────────────────────────
 *   ① 令牌只从 DSH 凭据库读，**绝不落盘、绝不打印**；
 *   ② 推送时写一个**临时**凭据文件交给 git（`credential.helper=store --file=…`），
 *      push 完立刻删除 —— 这样令牌不会进入 `.git/config`，也不会出现在命令行参数里；
 *   ③ 远端仓库地址始终用**不含令牌**的形式（`https://github.com/owner/repo.git`）。
 *
 * ── 为什么两端用同一份 tag 与同一份 release 说明 ─────────────────────────────
 * 需求是"GitHub 与 Gitee 同步发布"。所以 tag 名、release 名称、release 正文
 * 都取自同一处（`CHANGELOG.md` 里对应版本的那一节），避免两边说法不一致。
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { githubLogin, giteeLogin, readTokens } from './verify-tokens.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const apply = process.argv.includes('--apply');
const REPO = 'vmprobe';
const DESCRIPTION = 'VMProbe —— 单台云服务器的虚拟机探针：DSH 主控端插件 + Linux 协从端（受控动作 + 审批 + 审计链）';

const log = (s = '') => console.log(s);
const step = (s) => console.log(`\n▶ ${s}`);
const git = (args, opts = {}) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', ...opts });

/** 从 CHANGELOG 里取出某个版本的说明（release 正文两端共用）。 */
export function changelogSection(tag) {
  const version = tag.replace(/^v/, '');
  const text = readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8');
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`## v${version}`));
  if (start === -1) throw new Error(`CHANGELOG.md 里找不到 v${version} 的小节`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (lines[i].startsWith('## ')) { end = i; break; }
  }
  return lines.slice(start, end).join('\n').trim();
}

function tagExists(tag) {
  try {
    git(['rev-parse', '-q', '--verify', `refs/tags/${tag}`]);
    return true;
  } catch {
    return false;
  }
}

async function ensureGithub(token, login, tag, body) {
  const headers = {
    Authorization: `Bearer ${token}`,
    'User-Agent': 'vmprobe-release',
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
  };
  const base = `https://api.github.com/repos/${login}/${REPO}`;

  const head = await fetch(base, { headers });
  if (head.status === 404) {
    log(`  GitHub 仓库不存在 → 创建 ${login}/${REPO}`);
    if (apply) {
      const res = await fetch('https://api.github.com/user/repos', {
        method: 'POST',
        headers,
        body: JSON.stringify({ name: REPO, description: DESCRIPTION, private: false, has_issues: true, has_wiki: false }),
      });
      if (!res.ok) throw new Error(`创建 GitHub 仓库失败：HTTP ${res.status} ${await res.text()}`);
      log('  已创建');
    }
  } else if (head.ok) {
    log(`  GitHub 仓库已存在：${login}/${REPO}`);
  } else {
    throw new Error(`查询 GitHub 仓库失败：HTTP ${head.status}`);
  }

  log(`  GitHub remote = https://github.com/${login}/${REPO}.git`);
  if (!apply) { log('  （预演：跳过推送与 release 创建）'); return { pushed: false }; }
  return { pushed: true };
}

async function ensureGitee(token, login, tag, body) {
  const repoApi = `https://gitee.com/api/v5/repos/${login}/${REPO}`;
  const head = await fetch(`${repoApi}?access_token=${encodeURIComponent(token)}`);
  if (head.status === 404) {
    log(`  Gitee 仓库不存在 → 创建 ${login}/${REPO}`);
    if (apply) {
      const res = await fetch('https://gitee.com/api/v5/user/repos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_token: token, name: REPO, description: DESCRIPTION, private: false, has_issues: true }),
      });
      if (!res.ok) throw new Error(`创建 Gitee 仓库失败：HTTP ${res.status} ${await res.text()}`);
      log('  已创建');
    }
  } else if (head.ok) {
    log(`  Gitee 仓库已存在：${login}/${REPO}`);
  } else {
    throw new Error(`查询 Gitee 仓库失败：HTTP ${head.status}`);
  }

  log(`  Gitee remote = https://gitee.com/${login}/${REPO}.git`);
  if (!apply) { log('  （预演：跳过推送与 release 创建）'); return { pushed: false }; }
  return { pushed: true };
}

/** 用临时凭据文件推送（令牌不进 .git/config，也不进命令行参数）。 */
function pushWithTempCreds(remoteUrl, refs, tokens) {
  const tmpDir = mkdtempSync(join(tmpdir(), 'vmprobe-git-'));
  const credFile = join(tmpDir, '.git-credentials');
  const lines = [];
  for (const t of tokens) {
    if (!t.token) continue;
    const host = new URL(remoteUrl).host;
    lines.push(`https://${t.login}:${encodeURIComponent(t.token)}@${host}`);
  }
  writeFileSync(credFile, `${lines.join('\n')}\n`, { encoding: 'utf8', mode: 0o600 });
  try {
    execFileSync('git', [
      '-c', `credential.helper=store --file=${credFile}`,
      'push', remoteUrl, ...refs,
    ], { cwd: ROOT, stdio: 'inherit' });
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function createGithubRelease(token, login, tag, body) {
  const res = await fetch(`https://api.github.com/repos/${login}/${REPO}/releases`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'vmprobe-release',
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tag_name: tag, name: tag, body, draft: false, prerelease: false }),
  });
  if (res.status === 422) { log('  GitHub release 已存在（422）→ 跳过'); return null; }
  if (!res.ok) throw new Error(`创建 GitHub release 失败：HTTP ${res.status} ${await res.text()}`);
  const json = await res.json();
  log(`  GitHub release: ${json.html_url}`);
  return json.html_url;
}

async function createGiteeRelease(token, login, tag, body) {
  const res = await fetch(`https://gitee.com/api/v5/repos/${login}/${REPO}/releases`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_token: token, tag_name: tag, name: tag, body, target_commitish: 'main', prerelease: false }),
  });
  if (!res.ok) throw new Error(`创建 Gitee release 失败：HTTP ${res.status} ${await res.text()}`);
  const json = await res.json();
  log(`  Gitee release: ${json.html_url ?? `（已创建 ${tag}）`}`);
  return json.html_url ?? null;
}

// ─────────────────────────────────────────────────────────────────────────────

const tag = (() => {
  const i = process.argv.indexOf('--tag');
  if (i !== -1 && process.argv[i + 1]) return process.argv[i + 1];
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  return `v${pkg.version}`;
})();

log(`VMProbe 发布${apply ? '（--apply：会改动远端）' : '（预演，不改动远端）'}`);
log(`目标 tag：${tag}`);

const body = changelogSection(tag);
log(`release 说明：取自 CHANGELOG.md 的 ${tag} 小节（${body.split('\n').length} 行）`);

step('检查工作区与提交');
const dirty = git(['status', '--porcelain']).trim();
if (dirty) log(`  ⚠ 工作区有未提交改动（发布前应提交干净）：\n${dirty.split('\n').map((l) => `    ${l}`).join('\n')}`);
else log('  工作区干净');
log(`  当前提交：${git(['log', '-1', '--oneline']).trim()}`);

step('准备 tag');
if (tagExists(tag)) log(`  ${tag} 已存在（沿用）`);
else if (apply) {
  git(['tag', '-a', tag, '-m', `${tag}（见 CHANGELOG.md）`]);
  log(`  已创建 ${tag}`);
} else log(`  ${tag} 不存在（预演：跳过创建）`);

step('读取令牌');
const tokens = await readTokens();
const githubToken = tokens.github;
const giteeToken = tokens.gitee;
if (!githubToken && !giteeToken) throw new Error('两个平台的令牌都没有配置，无法发布');
const ghLogin = githubToken ? await githubLogin(githubToken) : null;
const gtLogin = giteeToken ? await giteeLogin(giteeToken) : null;
log(`  GitHub: ${ghLogin ?? '（未配置 → 跳过）'}`);
log(`  Gitee : ${gtLogin ?? '（未配置 → 跳过）'}`);

const results = { github: null, gitee: null };

if (ghLogin) {
  step('GitHub');
  await ensureGithub(githubToken, ghLogin, tag, body);
  if (apply) {
    pushWithTempCreds(`https://github.com/${ghLogin}/${REPO}.git`, ['main', '--tags'], [{ login: ghLogin, token: githubToken }]);
    log('  已推送 main 与 tags');
    results.github = await createGithubRelease(githubToken, ghLogin, tag, body);
  }
}

if (gtLogin) {
  step('Gitee');
  await ensureGitee(giteeToken, gtLogin, tag, body);
  if (apply) {
    pushWithTempCreds(`https://gitee.com/${gtLogin}/${REPO}.git`, ['main', '--tags'], [{ login: gtLogin, token: giteeToken }]);
    log('  已推送 main 与 tags');
    results.gitee = await createGiteeRelease(giteeToken, gtLogin, tag, body);
  }
}

step('结果');
if (!apply) log('  预演完成。加 --apply 执行。');
else {
  log(`  GitHub: ${results.github ?? `https://github.com/${ghLogin}/${REPO}`}`);
  log(`  Gitee : ${results.gitee ?? `https://gitee.com/${gtLogin}/${REPO}`}`);
}
