/**
 * 从 DSH 凭据库里**按需取用**发布所需的令牌，并做一次连通性自检。
 *
 * 三条纪律（与项目其它部分一致）：
 *   ① **绝不打印令牌**：只打印用户名与"是否可用"，连长度都不打；
 *   ② **不把令牌写进任何文件**：推送时用临时凭据文件，用完立即删除；
 *   ③ **不猜账号**：用户名一律向 API 问，不从配置里推断。
 *
 *   node tools/release/verify-tokens.mjs
 */

import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { importDshPackage } from '../lib/dsh-runtime.mjs';

const HOME = process.env.DSH_HOME ?? join(homedir(), '.dsh');
const CRED = join(HOME, '.credentials.yaml');

/** 读取凭据（值只在本进程内存里，不落盘、不回显）。 */
export async function readTokens() {
  if (!existsSync(CRED)) throw new Error(`找不到凭据文件：${CRED}`);
  const YAML = await importDshPackage('yaml');
  const doc = YAML.parse(readFileSync(CRED, 'utf8')) ?? {};
  const pick = (k) => (typeof doc[k] === 'string' && doc[k].trim() ? doc[k].trim() : null);
  return {
    github: pick('GITHUB_TOKEN'),
    gitee: pick('GITEE_TOKEN'),
  };
}

/** 向 GitHub 问"我是谁"。 */
export async function githubLogin(token) {
  const res = await fetch('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'vmprobe-release', Accept: 'application/vnd.github+json' },
  });
  if (!res.ok) throw new Error(`GitHub /user 失败：HTTP ${res.status}（令牌可能过期或权限不足）`);
  const me = await res.json();
  return me.login;
}

/** 向 Gitee 问"我是谁"。Gitee 用 access_token 查询参数。 */
export async function giteeLogin(token) {
  const res = await fetch(`https://gitee.com/api/v5/user?access_token=${encodeURIComponent(token)}`);
  if (!res.ok) throw new Error(`Gitee /user 失败：HTTP ${res.status}（令牌可能过期或权限不足）`);
  const me = await res.json();
  return me.login ?? me.name;
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}`) {
  const tokens = await readTokens();
  console.log('凭据文件：已找到');
  for (const [name, token] of Object.entries(tokens)) {
    if (!token) { console.log(`  ${name}: ✖ 未配置`); continue; }
    try {
      const login = name === 'github' ? await githubLogin(token) : await giteeLogin(token);
      console.log(`  ${name}: ✔ 可用（账号 ${login}）`);
    } catch (err) {
      console.log(`  ${name}: ✖ ${err.message}`);
    }
  }
}
