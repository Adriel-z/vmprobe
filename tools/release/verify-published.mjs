/**
 * 核对发布结果：两个平台的仓库、tag、release 是否都在。
 *
 *   node tools/release/verify-published.mjs [tag]
 */

import { readTokens, githubLogin, giteeLogin } from './verify-tokens.mjs';

const tag = process.argv[2] ?? 'v0.2.0';
const REPO = 'vmprobe';
const tokens = await readTokens();

const check = (ok, label, detail = '') => console.log(`  ${ok ? '✔' : '✖'} ${label}${detail ? ` —— ${detail}` : ''}`);

if (tokens.github) {
  const login = await githubLogin(tokens.github);
  const headers = { Authorization: `Bearer ${tokens.github}`, 'User-Agent': 'vmprobe-verify', Accept: 'application/vnd.github+json' };
  console.log(`\nGitHub (${login}/${REPO})`);
  const repo = await fetch(`https://api.github.com/repos/${login}/${REPO}`, { headers });
  check(repo.ok, '仓库存在', repo.ok ? (await repo.json()).html_url : `HTTP ${repo.status}`);
  const ref = await fetch(`https://api.github.com/repos/${login}/${REPO}/git/ref/tags/${tag}`, { headers });
  check(ref.ok, `tag ${tag}`, ref.ok ? '已推送' : `HTTP ${ref.status}`);
  const rel = await fetch(`https://api.github.com/repos/${login}/${REPO}/releases/tags/${tag}`, { headers });
  if (rel.ok) {
    const j = await rel.json();
    check(true, 'release', `${j.html_url}（正文 ${j.body?.length ?? 0} 字符，${j.assets?.length ?? 0} 个附件）`);
  } else check(false, 'release', `HTTP ${rel.status}`);
  const commits = await fetch(`https://api.github.com/repos/${login}/${REPO}/commits?per_page=1`, { headers });
  if (commits.ok) {
    const j = await commits.json();
    check(true, '提交', `${j[0]?.sha?.slice(0, 7)} ${j[0]?.commit?.message?.split('\n')[0]}`);
  }
}

if (tokens.gitee) {
  const login = await giteeLogin(tokens.gitee);
  const q = `access_token=${encodeURIComponent(tokens.gitee)}`;
  console.log(`\nGitee (${login}/${REPO})`);
  const repo = await fetch(`https://gitee.com/api/v5/repos/${login}/${REPO}?${q}`);
  check(repo.ok, '仓库存在', repo.ok ? (await repo.json()).html_url : `HTTP ${repo.status}`);
  const tags = await fetch(`https://gitee.com/api/v5/repos/${login}/${REPO}/tags?${q}`);
  if (tags.ok) {
    const list = await tags.json();
    check(list.some((t) => t.name === tag), `tag ${tag}`, `共 ${list.length} 个 tag`);
  } else check(false, `tag ${tag}`, `HTTP ${tags.status}`);
  const rel = await fetch(`https://gitee.com/api/v5/repos/${login}/${REPO}/releases/tags/${tag}?${q}`);
  if (rel.ok) {
    const j = await rel.json();
    check(true, 'release', `${j.html_url ?? '(无 html_url)'}（正文 ${j.body?.length ?? 0} 字符）`);
  } else check(false, 'release', `HTTP ${rel.status}`);
  const commits = await fetch(`https://gitee.com/api/v5/repos/${login}/${REPO}/commits?${q}&per_page=1`);
  if (commits.ok) {
    const j = await commits.json();
    const c = Array.isArray(j) ? j[0] : null;
    if (c) check(true, '提交', `${String(c.sha).slice(0, 7)} ${String(c.commit?.message ?? '').split('\n')[0]}`);
  }
}

console.log('');
