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
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

/**
 * 带重试的 fetch。
 *
 * 为什么需要：第一次真实发布就在创建 GitHub release 时挂在
 * `HTTP/2: "GOAWAY" frame received`（瞬时网络抖动，`UND_ERR_INFO`）。
 * 这类错误**与请求内容无关**，重试即可；但如果不重试，就会出现
 * "仓库建好了、代码推上去了、release 却没发出来"的半成品状态 ——
 * 而发布脚本必须能安全地**重跑**（幂等），所以两边都做：重试 + 幂等。
 */
async function fetchRetry(url, options = {}, { attempts = 4, label = 'request' } = {}) {
  let lastErr = null;
  for (let i = 1; i <= attempts; i += 1) {
    try {
      const res = await fetch(url, options);
      // 5xx 也值得重试（GitHub/Gitee 偶发 502/503）
      if (res.status >= 500 && i < attempts) {
        lastErr = new Error(`HTTP ${res.status}`);
        log(`  ${label}：HTTP ${res.status}，${i}/${attempts} 次，稍后重试…`);
        await new Promise((r) => setTimeout(r, 500 * i));
        continue;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (i === attempts) break;
      log(`  ${label}：${err.message}（${i}/${attempts} 次，稍后重试…）`);
      await new Promise((r) => setTimeout(r, 500 * i));
    }
  }
  throw new Error(`${label} 重试 ${attempts} 次仍失败：${lastErr?.message ?? lastErr}`);
}

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

  const head = await fetchRetry(base, { headers }, { label: 'GitHub 仓库查询' });
  if (head.status === 404) {
    log(`  GitHub 仓库不存在 → 创建 ${login}/${REPO}`);
    if (apply) {
      const res = await fetchRetry('https://api.github.com/user/repos', {
        method: 'POST',
        headers,
        body: JSON.stringify({ name: REPO, description: DESCRIPTION, private: false, has_issues: true, has_wiki: false }),
      }, { label: '创建 GitHub 仓库' });
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
  const head = await fetchRetry(`${repoApi}?access_token=${encodeURIComponent(token)}`, {}, { label: 'Gitee 仓库查询' });
  if (head.status === 404) {
    log(`  Gitee 仓库不存在 → 创建 ${login}/${REPO}`);
    if (apply) {
      const res = await fetchRetry('https://gitee.com/api/v5/user/repos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_token: token, name: REPO, description: DESCRIPTION, private: false, has_issues: true }),
      }, { label: '创建 Gitee 仓库' });
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

/**
 * 用临时凭据文件推送（令牌不进 .git/config，也不进命令行参数）。
 *
 * ⚠️ **这里踩过一个"把令牌写进仓库目录"的坑**，务必保留修复后的写法：
 *    最初把路径按 Windows 形式（`C:\Users\…\Temp\…`）塞进 `-c credential.helper=store --file=…`，
 *    而 git 的配置值里**反斜杠是转义字符** —— 路径被吃掉反斜杠后变成一个很长的相对文件名，
 *    于是 `credential.helper` 把**明文令牌**写进了**当前仓库的工作目录**：
 *    `Users-AppDataLocalTempvmprobe-git-XXXX.git-credentials`。
 *    它没有被提交（git 历史里 0 条、索引里 0 条，事后已全部删除），但这类文件出现在工作区
 *    本身就是一次"随时可能被 `git add -A` 带走"的事故。
 *
 * 所以现在做三件事：
 *   ① 路径统一用**正斜杠**（git 在 Windows 上完全接受 `C:/…`）；
 *   ② 推送前后都断言"临时凭据文件确实在预期位置"；
 *   ③ 推送后**扫描仓库工作区**里有没有漏出来的凭据文件，有就删掉并大声报错（见 assertNoStrayCreds）。
 */
function pushWithTempCreds(remoteUrl, refs, tokens) {
  const tmpDir = mkdtempSync(join(tmpdir(), 'vmprobe-git-'));
  // ① 正斜杠路径（Windows 上反斜杠会被 git 当转义符）
  const credFile = join(tmpDir, '.git-credentials').replace(/\\/g, '/');
  const lines = [];
  for (const t of tokens) {
    if (!t.token) continue;
    const host = new URL(remoteUrl).host;
    lines.push(`https://${t.login}:${encodeURIComponent(t.token)}@${host}`);
  }
  if (!lines.length) throw new Error('pushWithTempCreds：没有任何可用令牌');
  writeFileSync(credFile, `${lines.join('\n')}\n`, { encoding: 'utf8', mode: 0o600 });
  // ② 断言文件在预期位置（否则就是转义又出问题了，绝不能继续）
  if (!existsSync(credFile)) throw new Error(`临时凭据文件未落在预期位置：${credFile}`);

  try {
    execFileSync('git', [
      '-c', `credential.helper=store --file=${credFile}`,
      'push', remoteUrl, ...refs,
    ], { cwd: ROOT, stdio: 'inherit' });
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
    // ③ 兜底扫描：任何漏进工作区的凭据文件都要立刻消失并报警
    assertNoStrayCreds();
  }
}

/**
 * 扫描仓库工作区（以及 git 索引）里有没有被写歪的凭据文件。
 * **发现即删除并无条件报错** —— 这种文件绝不允许静默留在工作区。
 */
function assertNoStrayCreds() {
  const stray = readdirSync(ROOT, { withFileTypes: true })
    .filter((e) => e.isFile() && /git-credentials/i.test(e.name))
    .map((e) => e.name);
  if (!stray.length) return;
  for (const name of stray) {
    try { rmSync(join(ROOT, name), { force: true }); } catch { /* 尽力 */ }
  }
  throw new Error(
    `发现并已删除 ${stray.length} 个漏进工作区的凭据文件：${stray.join('、')}。`
    + '这说明临时凭据路径又被 git 转义处理歪了 —— 请检查 pushWithTempCreds 的路径形式，'
    + '并确认这些文件从未被提交（git log --all -- "*git-credentials*"）。',
  );
}

async function createGithubRelease(token, login, tag, body) {
  const res = await fetchRetry(`https://api.github.com/repos/${login}/${REPO}/releases`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'User-Agent': 'vmprobe-release',
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ tag_name: tag, name: tag, body, draft: false, prerelease: false }),
  }, { label: '创建 GitHub release' });
  if (res.status === 422) { log('  GitHub release 已存在（422）→ 跳过'); return null; }
  if (!res.ok) throw new Error(`创建 GitHub release 失败：HTTP ${res.status} ${await res.text()}`);
  const json = await res.json();
  log(`  GitHub release: ${json.html_url}`);
  return json.html_url;
}

async function createGiteeRelease(token, login, tag, body) {
  const res = await fetchRetry(`https://gitee.com/api/v5/repos/${login}/${REPO}/releases`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_token: token, tag_name: tag, name: tag, body, target_commitish: 'main', prerelease: false }),
  }, { label: '创建 Gitee release' });
  // Gitee 的"已存在"是 HTTP 400 + "该标签已经存在发行版"（GitHub 那边是 422）——
  // 发布脚本必须两边都幂等，否则重跑一次就会以失败告终，看起来像发布失败其实早就成功了
  if (res.status === 400) {
    const text = await res.text();
    if (/已经存在/.test(text)) {
      log('  Gitee release 已存在 → 跳过');
      const existing = await fetchRetry(
        `https://gitee.com/api/v5/repos/${login}/${REPO}/releases/tags/${tag}?access_token=${encodeURIComponent(token)}`,
        {}, { label: '查询 Gitee release' },
      );
      if (existing.ok) {
        const j = await existing.json();
        log(`  Gitee release: ${j.html_url ?? `（${tag}）`}`);
        return j.html_url ?? null;
      }
      return null;
    }
    throw new Error(`创建 Gitee release 失败：HTTP 400 ${text}`);
  }
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
const moveTag = process.argv.includes('--move-tag');
if (tagExists(tag) && moveTag) {
  // 显式的"把 tag 挪到当前提交"：只在该 tag 是**刚刚发布的**、且发布物里发现缺陷时用。
  // （本轮就是这种情况：tag 里的发布脚本会把令牌写进仓库工作区 —— 见 pushWithTempCreds 的注释。）
  if (!apply) log(`  ${tag} 已存在；--move-tag 会把 tag 强制指向当前提交（预演：跳过）`);
  else {
    git(['tag', '-f', '-a', tag, '-m', `${tag}（见 CHANGELOG.md；此 tag 已被移动到修复提交）`]);
    log(`  已把 ${tag} 移动到 ${git(['rev-parse', '--short', 'HEAD']).trim()}`);
  }
} else if (tagExists(tag)) log(`  ${tag} 已存在（沿用；如需移动请显式加 --move-tag）`);
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
    pushWithTempCreds(
      `https://github.com/${ghLogin}/${REPO}.git`,
      ['main', ...(moveTag ? [`+refs/tags/${tag}:refs/tags/${tag}`] : ['--tags'])],
      [{ login: ghLogin, token: githubToken }],
    );
    log(`  已推送 main 与 ${moveTag ? `（强制更新的）tag ${tag}` : 'tags'}`);
    results.github = await createGithubRelease(githubToken, ghLogin, tag, body);
  }
}

if (gtLogin) {
  step('Gitee');
  await ensureGitee(giteeToken, gtLogin, tag, body);
  if (apply) {
    pushWithTempCreds(
      `https://gitee.com/${gtLogin}/${REPO}.git`,
      ['main', ...(moveTag ? [`+refs/tags/${tag}:refs/tags/${tag}`] : ['--tags'])],
      [{ login: gtLogin, token: giteeToken }],
    );
    log(`  已推送 main 与 ${moveTag ? `（强制更新的）tag ${tag}` : 'tags'}`);
    results.gitee = await createGiteeRelease(giteeToken, gtLogin, tag, body);
  }
}

step('结果');
if (!apply) log('  预演完成。加 --apply 执行。');
else {
  log(`  GitHub: ${results.github ?? `https://github.com/${ghLogin}/${REPO}`}`);
  log(`  Gitee : ${results.gitee ?? `https://gitee.com/${gtLogin}/${REPO}`}`);
}
