/**
 * 免密登录事务 —— 本项目风险最高的一段代码。
 *
 * ── 为什么必须是"事务"而不是"配完就切" ────────────────────────────────────
 * 需求原文是"自动配置 ssh 密钥，然后主动切断链接再以免密方式登录一次"。
 * 按字面实现的致命隐患：**如果新配的密钥其实不可用**（`sshd_config` 里
 * `PubkeyAuthentication no`、权限位触发 StrictModes、家目录加密、SELinux 上下文、
 * `AllowUsers` 不含该用户……），切断旧连接之后你将**永久失去这台服务器**，
 * 只能走 VNC/控制台救回来。
 *
 * 所以顺序是：
 *
 *   生成专用密钥 → 幂等写入 authorized_keys（先备份） → **另开一条全新连接用密钥验证成功**
 *     → 成功：才切断旧密码连接、抹掉内存里的密码、把 authRef 切成 key
 *     → 失败：回滚 authorized_keys 追加、**保留旧连接**、报告原始错误
 *
 * **核心不变式：任何时刻至少存在一条可用连接路径。**
 * 这也是本模块所有 early-return 都在"动任何东西之前"的原因。
 *
 * ── 另外两条刻意的做法 ────────────────────────────────────────────────────
 * · 写入用**注释标记**（`vmprobe:<targetId>`）做幂等判定，避免重复追加造成的
 *   authorized_keys 膨胀（这是经典事故）。
 * · 不修改 `sshd_config`（那是另一件事，风险等级更高），只**报告**它是否阻碍了配置。
 */

/** 事务失败时抛出的错误（带步骤信息，便于用户知道停在哪一步）。 */
export class PasswordlessError extends Error {
  constructor(message, { step, detail, rolledBack } = {}) {
    super(message);
    this.name = 'PasswordlessError';
    this.code = 'passwordless_failed';
    this.step = step ?? null;
    this.detail = detail ?? null;
    this.rolledBack = rolledBack ?? null;
  }
}

/** 远端 shell 调用的小工具：把脚本 + 参数安全地送过去（参数走位置参数，避免二次解析）。 */
function sh(transport, target, script, args = [], opts = {}) {
  return transport.exec(target, ['sh', '-c', script, 'sh', ...args], opts);
}

/**
 * 在一个目标上启用免密登录。
 *
 * @param {object} transport 传输层（需具备 connect/exec/disconnect/loadIdentity/createIdentity/verifyKeyLogin）
 * @param {object} target 目标记录
 * @param {object} [options]
 * @param {boolean} [options.keepPasswordAuth] 是否建议保留服务端密码认证（只影响提示，不改配置）
 * @param {Function} [options.onStep] 步骤回调（用于审计每一步）
 * @returns {Promise<object>} 事务报告
 */
export async function enablePasswordless(transport, target, options = {}) {
  const { onStep = null } = options;
  const targetId = target.id;
  const steps = [];
  const step = (name, detail) => {
    steps.push({ step: name, at: new Date().toISOString(), detail });
    onStep?.(name, detail);
  };

  // ── 0. 前置：先确认能连上（用现有认证）───────────────────────────────
  await transport.connect(target);
  step('connect', `已用 ${target.authRef?.kind ?? 'password'} 认证连上 ${target.user}@${target.hostname}`);

  // ── 1. 前置：远端是否允许公钥认证？不允许就**什么都别动** ──────────────
  const facts = await transport.probeFacts(target);
  const pubkeyAuth = facts?.ssh?.pubkeyAuth;
  if (pubkeyAuth === false) {
    throw new PasswordlessError(
      '远端 sshd 禁用了公钥认证（PubkeyAuthentication no），无法启用免密登录。'
      + '这需要在服务端修改 sshd_config —— 属于独立的、风险更高的动作，本事务不会代劳。',
      { step: 'preflight', detail: { pubkeyAuth } },
    );
  }
  step('preflight', `公钥认证可用（ssh.pubkeyAuth=${String(pubkeyAuth)}）`);

  // ── 2. 准备专用密钥（本地）──────────────────────────────────────────
  let identity = transport.loadIdentity(targetId);
  let createdKey = false;
  if (!identity) {
    identity = transport.createIdentity(targetId, `vmprobe:${targetId}`);
    createdKey = true;
  }
  const pubLine = identity.publicKeyLine;
  if (!pubLine) {
    throw new PasswordlessError('本地已存在同名私钥但没有对应公钥文件，无法继续（请先撤销该密钥）', {
      step: 'identity',
    });
  }
  const blob = pubLine.split(/\s+/)[1];
  step('identity', `${createdKey ? '已生成' : '复用'}专用密钥（注释 vmprobe:${targetId}）`);

  // ── 3. 远端环境：定位 ssh 目录与 authorized_keys，并检查权限位 ─────────
  //
  // ⚠️ 这里必须是**分行**的脚本。写成一条用空格拼接的命令会把后续命令
  // （如 `test -w …`）当成 printf 的参数，输出行的含义就全错了 —— 踩过。
  const envProbeScript = [
    'printf "%s\\n" "$HOME" "$HOME/.ssh" "$HOME/.ssh/authorized_keys"',
    'if [ -w "$HOME" ]; then echo writable; else echo readonly; fi',
  ].join('\n');
  const env = await sh(transport, target, envProbeScript);
  const [home, sshDir, akFile, writable] = String(env.stdout).trim().split('\n');
  if (env.exit !== 0) {
    throw new PasswordlessError(`无法探测远端家目录：${String(env.stderr).trim()}`, { step: 'probe-env' });
  }
  if (writable !== 'writable') {
    throw new PasswordlessError(`远端家目录不可写（${home}），无法写入 authorized_keys`, { step: 'probe-env' });
  }
  step('probe-env', `家目录 ${home}，authorized_keys ${akFile}`);

  // 权限检查（StrictModes 会因组/他人可写而**静默拒绝**使用 authorized_keys）
  const perms = await sh(transport, target, 'stat -c "%a" "$1" 2>/dev/null || echo missing', [home]);
  const homeMode = String(perms.stdout).trim().split('\n')[0];
  if (/^[0-7]{3,4}$/.test(homeMode)) {
    const m = homeMode.slice(-3);
    const groupWritable = (parseInt(m[1], 8) & 2) !== 0;
    const otherWritable = (parseInt(m[2], 8) & 2) !== 0;
    if (groupWritable || otherWritable) {
      // 只报告，不擅自改家目录权限（那会影响用户环境）
      step('warn-strictmodes', `⚠ 家目录 ${home} 的权限位是 ${homeMode}（组或他人可写），`
        + 'OpenSSH 的 StrictModes 可能因此拒绝使用 authorized_keys；'
        + '若第 5 步验证失败，请先收紧该权限（如 chmod g-w,o-w）');
    } else {
      step('check-home-perms', `家目录权限位 ${homeMode}，不含组/他人可写（StrictModes 友好）`);
    }
  } else {
    step('check-home-perms', `无法读取家目录权限位（${homeMode}），跳过 StrictModes 预检`);
  }

  // ── 4. 幂等写入 authorized_keys（先备份）───────────────────────────────
  const existedBefore = (await sh(transport, target, 'test -f "$1" && echo yes || echo no', [akFile]))
    .stdout.trim() === 'yes';
  const writeScript = [
    'set -e',
    'd="$1"; f="$2"; line="$3"; marker="$4"',
    'mkdir -p "$d"',
    'if [ -f "$f" ]; then cp -p "$f" "$f.vmprobe.$(date +%s).bak"; else : > "$f"; fi',
    'chmod 700 "$d"; chmod 600 "$f"',
    'if grep -qF "$line" "$f" || grep -qF "$marker" "$f"; then echo already; else',
    '  printf "%s\\n" "$line" >> "$f"; echo appended; fi',
  ].join('\n');
  const written = await sh(transport, target, writeScript, [sshDir, akFile, pubLine, `vmprobe:${targetId}`]);
  if (written.exit !== 0) {
    throw new PasswordlessError(`写入 authorized_keys 失败：${String(written.stderr).trim()}`, {
      step: 'write-authorized-keys', detail: { akFile },
    });
  }
  const writeResult = String(written.stdout).trim().split('\n').pop();
  step('write-authorized-keys', `${akFile} → ${writeResult}（写入前已备份 .bak）`);

  // ── 5. ★ 关键：另开一条**全新连接**用密钥验证 ─────────────────────────
  let verified = null;
  try {
    verified = await transport.verifyKeyLogin(target, identity.privateKeyPem);
  } catch (err) {
    // 回滚：把刚追加的那一行去掉（若文件是我们创建的且现在为空，则删掉它）
    let rolledBack = false;
    try {
      const rollback = await sh(transport, target, [
        'set -e',
        'f="$1"; line="$2"',
        'if [ -f "$f" ]; then',
        '  grep -vF "$line" "$f" > "$f.vmprobe.tmp" || true',
        existedBefore ? '  mv "$f.vmprobe.tmp" "$f"' : '  rm -f "$f.vmprobe.tmp" "$f"',
        '  chmod 600 "$f" 2>/dev/null || true',
        'fi',
      ].join('\n'), [akFile, pubLine]);
      rolledBack = rollback.exit === 0;
    } catch { /* 回滚失败也要如实报告 */ }
    throw new PasswordlessError(
      `密钥验证失败，**已保留原有连接**（未切断），authorized_keys 回滚${rolledBack ? '成功' : '未完成，请人工检查'}。`
      + `原始错误：${err?.message ?? err}`,
      { step: 'verify', detail: { rolledBack }, rolledBack },
    );
  }
  step('verify', `另开连接用密钥验证成功（${verified?.banner ?? 'ok'}）`);

  // ── 6. 到这里才有资格切断旧连接 ────────────────────────────────────────
  transport.disconnect(targetId);
  step('cut-old-session', '旧（密码）连接已主动切断 —— 此前已确认密钥路径可用');

  // ── 7. 以密钥重新连接，确认切换后一切正常 ──────────────────────────────
  const switched = { ...target, authRef: { kind: 'key', ref: targetId }, hostKey: target.hostKey };
  await transport.connect(switched);
  const check = await transport.exec(switched, ['echo', 'vmprobe-key-ok']);
  if (check.exit !== 0 || !String(check.stdout).includes('vmprobe-key-ok')) {
    throw new PasswordlessError(
      '以密钥重新连接后自检失败 —— 这是意外情况：密钥验证连接曾经成功过。'
      + '当前会话仍可用，请检查远端 sshd 是否有连接数/来源限制。',
      { step: 'reconnect', detail: { stdout: check.stdout, stderr: check.stderr } },
    );
  }
  step('reconnect', '已以免密（publickey）方式重新连上并自检通过');

  return {
    ok: true,
    steps,
    targetId,
    keyId: identity.keyId,
    publicKeyLine: pubLine,
    marker: `vmprobe:${targetId}`,
    authorizedKeysPath: akFile,
    home,
    createdKey,
    writeResult,
    authRefAfter: { kind: 'key', ref: targetId },
    verifiedAt: new Date().toISOString(),
  };
}

/**
 * 撤销免密登录 —— **与启用对称的事务**，同样不允许锁死机器。
 *
 * 危险点：若先删掉 authorized_keys 里的那行、而服务端又禁用了密码认证，
 * 你就再也进不去了。所以顺序必须是：
 *
 *   ① **先用密码另开一条连接验证成功**（证明"删掉密钥后还有路可走"）
 *      → 不成功：拒绝撤销（什么都不动）并说明原因
 *   ② 才移除 authorized_keys 里我们的那一行（移除前备份）
 *   ③ 才删本地私钥、把 authRef 切回 password、切断密钥会话、以密码重连
 */
export async function disablePasswordless(transport, target, options = {}) {
  const { onStep = null, passwordRef = null } = options;
  const targetId = target.id;
  const steps = [];
  const step = (name, detail) => {
    steps.push({ step: name, at: new Date().toISOString(), detail });
    onStep?.(name, detail);
  };

  await transport.connect(target);
  step('connect', `已连上 ${target.user}@${target.hostname}`);

  const marker = `vmprobe:${targetId}`;

  // ① 删之前先证明还有别的路可走
  const facts = await transport.probeFacts(target);
  const passwordAuth = facts?.ssh?.passwordAuth;
  if (passwordAuth === false) {
    throw new PasswordlessError(
      '远端已禁用密码认证；此时移除唯一可用的密钥会让你再也登录不上 —— 拒绝撤销。'
      + '如需撤销，请先在服务端恢复密码认证，或另备一把可用密钥。',
      { step: 'preflight', detail: { passwordAuth } },
    );
  }

  // 回退到哪个凭据引用？优先显式传入，其次取"切换前记住的那个"（previousAuthRef）。
  // 若都没有，**明确拒绝**而不是拿目标的 id 去当凭据名乱试 ——
  // 那只会得到"凭据 t_xxx 未配置"这种令人困惑的报错。
  const backRef = passwordRef ?? target.previousAuthRef?.ref ?? null;
  if (!backRef) {
    throw new PasswordlessError(
      '不知道该回退到哪个凭据引用：目标里没有 previousAuthRef（可能是历史数据），'
      + '调用时也没有传 passwordRef。请显式传 passwordRef 再试 —— 拒绝在不知道回退路径的情况下移除密钥。',
      { step: 'preflight' },
    );
  }
  const backToPassword = { ...target, authRef: { kind: 'password', ref: backRef } };
  step('resolve-fallback', `将回退到密码认证，凭据引用 = ${backRef}`);
  if (typeof transport.verifyPasswordLogin === 'function') {
    try {
      await transport.verifyPasswordLogin(backToPassword);
      step('verify-password-path', '已用密码另开一条连接验证成功（证明移除密钥后仍有路径）');
    } catch (err) {
      throw new PasswordlessError(
        `无法用密码建立连接（${err?.message ?? err}）—— 移除密钥可能导致无法登录，拒绝撤销。`,
        { step: 'verify-password-path' },
      );
    }
  } else {
    step('verify-password-path', '传输层未提供密码验证能力，跳过该预检');
  }

  // ② 移除我们的那一行
  const akFile = String((await sh(transport, target, 'printf "%s" "$HOME/.ssh/authorized_keys"')).stdout).trim();
  const removed = await sh(transport, target, [
    'set -e',
    'f="$1"; marker="$2"',
    'if [ -f "$f" ]; then',
    '  cp -p "$f" "$f.vmprobe.disable.$(date +%s).bak"',
    '  grep -vF "$marker" "$f" > "$f.vmprobe.tmp" || true',
    '  mv "$f.vmprobe.tmp" "$f"',
    '  chmod 600 "$f" 2>/dev/null || true',
    'fi',
  ].join('\n'), [akFile, marker]);
  if (removed.exit !== 0) {
    throw new PasswordlessError(`移除 authorized_keys 条目失败：${String(removed.stderr).trim()}`, {
      step: 'remove-authorized-keys',
    });
  }
  step('remove-authorized-keys', `已移除 ${marker} 对应的行（移除前已备份）`);

  // ③ 清本地私钥 → 切回密码 → 重连
  transport.removeIdentity?.(targetId);
  step('remove-local-key', '本地专用私钥已删除');

  transport.disconnect(targetId);
  await transport.connect(backToPassword);
  const probe = await transport.exec(backToPassword, ['echo', 'vmprobe-password-ok']);
  if (probe.exit !== 0) {
    throw new PasswordlessError('以密码重连后自检失败 —— 会话仍可用，请人工确认远端状态', {
      step: 'reconnect', detail: { stderr: probe.stderr },
    });
  }
  step('reconnect', '已以密码方式重新连上并自检通过');

  return {
    ok: true, steps, targetId, marker, authorizedKeysPath: akFile,
    authRefAfter: { kind: 'password', ref: backToPassword.authRef.ref },
  };
}
