/**
 * SSH 传输层（ssh2 后端）。
 *
 * ── 三条设计决定 ──────────────────────────────────────────────────────────
 *
 * 1. **ssh2 而不是本地 OpenSSH 客户端**（设计决策 D2）。
 *    原因很实际：Windows 的 `ssh.exe` **无法从 stdin/env 接收密码**，也没有 sshpass 等价物，
 *    而"用密码首次登录"正是需求的第一步。ssh2 是纯 JS（无原生依赖即可运行），
 *    天然支持密码认证、单连接多通道复用、keepalive，Windows/Linux 行为一致，
 *    且**不要求本机装 OpenSSH**。
 *
 * 2. **保活是「内建」而非「配置」**：一条长连接 + 多个 exec channel 本身就是保活。
 *    再叠加 keepaliveInterval（SSH 层心跳）与 TCP keepalive。
 *    不需要 ControlMaster 那套 socket 文件（Windows 上 ControlPath 很麻烦）。
 *
 * 3. **文件投递走 exec + stdin**（`cat > 文件`），不用 SFTP。
 *    SSH 通道本就是 8 位透明的，这样少一个子系统依赖，也让测试台能真实覆盖它。
 *    SFTP 留给将来的大文件传输。
 *
 * ── 安全要点 ──────────────────────────────────────────────────────────────
 *
 * · **argv 必须逐个转义**。SSH 的 exec 语义是"把这一整行交给远端登录 shell 执行"，
 *   所以"不经 shell"不能靠设计声明，只能靠**正确引用**。见 `shQuote()`。
 * · **主机密钥固定**（TOFU）：首连接受并记录指纹，之后**严格比对**，不符即拒绝。
 *   指纹格式与 `ssh-keygen -lf` 一致，用户能独立核对 —— 否则防 MITM 只是形式。
 * · **密码不落地**：从凭据引用按需解析（每次操作现取，不缓存），用完即从内存抹掉。
 */

import { Client } from 'ssh2';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

import { generateKeypair, publicKeyFingerprint } from './keys.js';

/**
 * 按 `expect` 逐字段比对探测结果。
 *
 * **纯函数**（模块级，因此可以独立单测，不需要 SSH）。三条刻意的语义：
 *   · 只比对 `expect` 里**列出的**字段 —— 探测结果里的其它字段（如 `distro`）不参与判定；
 *   · `expect` 里出现而探测结果里**没有**的字段 ⇒ 不满足（绝不把"探测不到"当成"符合预期"）；
 *   · 没有 `expect` ⇒ 返回 `null`（**未判定**），而不是 `true` ——
 *     "探测跑过了"与"达到了目标态"是两件事，不能混为一谈。
 */
export function probeSatisfies(state, expect) {
  if (!expect || typeof expect !== 'object' || Array.isArray(expect)) return null;
  const keys = Object.keys(expect);
  if (!keys.length) return null;
  for (const key of keys) {
    if (!(key in (state ?? {}))) return false;      // 探测结果里没有这个字段 → 无法确认
    const actual = state[key];
    const wanted = expect[key];
    if (Array.isArray(wanted)) {
      if (!Array.isArray(actual) || actual.length !== wanted.length
        || wanted.some((v, i) => actual[i] !== v)) return false;
    } else if (actual !== wanted) {
      return false;
    }
  }
  return true;
}

/**
 * 从 AbortSignal 里取出可读的取消原因（用于错误文本）。
 * 宿主给的 reason 通常是 Error 或字符串，缺失时说"未给出原因"而不是编一个。
 */
export function whyCancelled(signal) {
  const reason = signal?.reason;
  if (!reason) return '未给出原因';
  if (typeof reason === 'string') return reason;
  return reason.message ?? String(reason);
}

/** 主机密钥与已固定值不符 —— 可能是重装，也可能是中间人。 */
export class HostKeyMismatchError extends Error {
  constructor(targetId, expected, actual) {
    super(
      `主机密钥与已固定值不符（目标 ${targetId}）：期望 ${expected}，实际 ${actual}。`
      + '可能是服务器重装，也可能是中间人攻击 —— 拒绝连接。确认无误后用主机密钥轮换动作接受新指纹。',
    );
    this.name = 'HostKeyMismatchError';
    this.code = 'host_key_mismatch';
    this.expected = expected;
    this.actual = actual;
  }
}

/** 首次连接、尚无已固定指纹 —— 需要用户确认后才固定（TOFU）。 */
export class HostKeyUnknownError extends Error {
  constructor(targetId, fingerprint) {
    super(
      `目标 ${targetId} 的主机密钥尚未固定，指纹为 ${fingerprint}。`
      + '请先用带 fingerprint 的目标更新动作固定它（或用 hostKeyPolicy=accept-new 接受首连）。',
    );
    this.name = 'HostKeyUnknownError';
    this.code = 'host_key_unknown';
    this.fingerprint = fingerprint;
  }
}

/**
 * POSIX 单引号转义。
 *
 * 这是**注入防线的全部**：SSH 会把命令行交给远端 shell，所以每个 argv 元素
 * 都必须被完整引用。`'` → `'\''` 是标准做法。
 */
export function shQuote(arg) {
  const s = String(arg);
  if (s === '') return "''";
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** 把 argv（+ 可选 env）拼成一条可安全交给远端 shell 的命令行。 */
export function buildCommand(argv, env = null) {
  const quoted = argv.map(shQuote);
  if (env && Object.keys(env).length) {
    const assigns = Object.entries(env).map(([k, v]) => shQuote(`${k}=${v}`));
    return ['env', ...assigns, ...quoted].map(shQuote).join(' ');
  }
  return quoted.join(' ');
}

const DEFAULT_MAX_OUTPUT = 1024 * 1024;

/**
 * 创建 SSH 传输层。
 *
 * @param {object} options
 * @param {(targetId: string) => Promise<object|null>} options.resolveTarget 按 id 取目标记录
 * @param {(ref: string) => Promise<string|undefined>} [options.resolveCredential] 解析凭据引用
 * @param {string} options.keyDir 专用私钥存放目录
 * @param {string} [options.agentScriptPath] 协从端引导脚本路径（用于经 stdin 投递）
 * @param {(targetId: string, fingerprint: string) => Promise<void>} [options.onHostKey] 首连/变更时回调（落库 + 审计）
 * @param {'accept-new'|'strict'} [options.hostKeyPolicy] 默认 accept-new（TOFU）；strict 要求已固定指纹
 */
export function createSshTransport(options) {
  const {
    resolveTarget,
    resolveCredential,
    keyDir,
    agentScriptPath = null,
    onHostKey = null,
    hostKeyPolicy = 'accept-new',
    connectTimeoutMs = 15000,
    commandTimeoutMs = 120000,
    maxOutputBytes = DEFAULT_MAX_OUTPUT,
    keepaliveInterval = 15000,
    keepaliveCountMax = 4,
    logger = null,
  } = options;

  if (!resolveTarget) throw new Error('createSshTransport 需要 resolveTarget');
  if (!keyDir) throw new Error('createSshTransport 需要 keyDir');
  mkdirSync(keyDir, { recursive: true });

  /** @type {Map<string, object>} targetId → 会话 */
  const sessions = new Map();

  const log = (level, msg) => logger?.[level]?.(msg);

  // ── 专用身份密钥（每个目标一把，便于单独撤销）──────────────────────────

  function identityPaths(targetId) {
    return {
      priv: join(keyDir, `${targetId}.ed25519`),
      pub: join(keyDir, `${targetId}.ed25519.pub`),
    };
  }

  function loadIdentity(targetId) {
    const { priv, pub } = identityPaths(targetId);
    if (!existsSync(priv)) return null;
    return {
      privateKeyPem: readFileSync(priv, 'utf8'),
      publicKeyLine: existsSync(pub) ? readFileSync(pub, 'utf8').trim() : null,
      keyId: targetId,
    };
  }

  function createIdentity(targetId, comment) {
    const pair = generateKeypair(comment);
    const { priv, pub } = identityPaths(targetId);
    writeFileSync(priv, pair.privateKeyPem, { mode: 0o600 });
    writeFileSync(pub, `${pair.publicKeyLine}\n`, { mode: 0o644 });
    try {
      chmodSync(priv, 0o600);
    } catch { /* Windows 无 chmod 语义，忽略 */ }
    return { privateKeyPem: pair.privateKeyPem, publicKeyLine: pair.publicKeyLine, keyId: targetId };
  }

  // ── 连接 ────────────────────────────────────────────────────────────────

  async function connect(target) {
    const targetId = target.id;
    const existing = sessions.get(targetId);
    if (existing && existing.state === 'connected') return existing;

    const authMode = target.authRef?.kind ?? 'password';
    let password;
    let privateKey;

    if (authMode === 'key') {
      const id = loadIdentity(targetId);
      if (!id) throw new Error(`目标 ${targetId} 声明用密钥认证，但本地没有专用密钥（可先执行 ssh.passwordless.enable）`);
      privateKey = id.privateKeyPem;
    } else {
      if (!resolveCredential) throw new Error('缺少凭据解析器，无法解析密码引用');
      const value = await resolveCredential(target.authRef?.ref);
      if (!value) {
        const err = new Error(
          `凭据 ${target.authRef?.ref ?? '(未设置引用)'} 尚未配置 —— `
          + '请用 tools/vmprobe-cred.mjs 录入（交互式无回显），不要把密码打在对话里。',
        );
        err.code = 'credential_missing';
        throw err;
      }
      password = value;
    }

    const pinned = target.hostKey?.fingerprint ?? null;
    let observedFingerprint = null;
    let hostKeyReject = null;

    const config = {
      host: target.hostname,
      port: target.port ?? 22,
      username: target.user,
      readyTimeout: connectTimeoutMs,
      keepaliveInterval,
      keepaliveCountMax,
      hostHash: 'sha256',
      hostVerifier: (hexHash) => {
        // ssh2 在 hostHash:'sha256' 时传入的是 **hex 字符串**（实测确认）
        const fp = `SHA256:${Buffer.from(hexHash, 'hex').toString('base64').replace(/=+$/, '')}`;
        observedFingerprint = fp;
        if (pinned && pinned !== fp) {
          hostKeyReject = new HostKeyMismatchError(targetId, pinned, fp);
          return false;
        }
        if (!pinned && hostKeyPolicy === 'strict') {
          hostKeyReject = new HostKeyUnknownError(targetId, fp);
          return false;
        }
        return true;
      },
    };
    if (privateKey) config.privateKey = privateKey;
    else config.password = password;

    const client = new Client();
    const session = {
      client, state: 'connecting', target, connectedAt: null, fingerprint: null, commands: 0,
    };
    sessions.set(targetId, session);

    try {
      await new Promise((resolve, reject) => {
        client.on('ready', resolve);
        client.on('error', (err) => reject(hostKeyReject ?? err));
        client.on('close', () => {
          const s = sessions.get(targetId);
          if (s && s.client === client) { s.state = 'detached'; s.client = null; }
        });
        client.connect(config);
      });
    } catch (err) {
      sessions.delete(targetId);
      // 密码用完立刻从内存抹掉
      if (password !== undefined) password = undefined;
      throw err;
    } finally {
      if (password !== undefined) password = undefined;
    }

    session.state = 'connected';
    session.connectedAt = new Date().toISOString();
    session.fingerprint = observedFingerprint;
    session.authMode = authMode;

    // 首连或指纹变化 → 交给上层落库 + 审计（auto R1）。失败不影响连接本身。
    if (onHostKey && observedFingerprint && observedFingerprint !== pinned) {
      try {
        await onHostKey(targetId, observedFingerprint);
      } catch (err) {
        log('warn', `vmprobe: 记录主机指纹失败（不影响连接）：${err?.message ?? err}`);
      }
    }
    log('info', `vmprobe: 已连接 ${target.user}@${target.hostname}:${target.port ?? 22}（认证 ${authMode}，指纹 ${observedFingerprint}）`);
    return session;
  }

  async function sessionFor(targetId) {
    const s = sessions.get(targetId);
    if (s && s.state === 'connected' && s.client) return s;
    const target = await resolveTarget(targetId);
    if (!target) throw new Error(`目标不存在：${targetId}`);
    return connect(target);
  }

  /**
   * 用会话执行一条命令（argv 会被逐个安全引用）。
   *
   * `opts.signal` 支持**真正的取消**（M2-③）：中断时与超时走**同一条**清理路径 ——
   * 先给通道发 TERM（让远端进程真的收到信号，而不是变成孤儿继续跑），3 秒后硬关通道。
   * 只 close 不 signal 的话，`apt-get` 这类命令会留在远端后台写一半状态。
   */
  function execOnSession(session, argv, opts = {}) {
    const {
      env = null, timeoutMs = commandTimeoutMs, input = undefined,
      binary = false, maxBytes = maxOutputBytes, signal = null,
    } = opts;

    const command = buildCommand(argv, env);
    return new Promise((resolve, reject) => {
      let settled = false;
      let streamRef = null;
      let onAbort = null;
      /** 非空表示"这次执行已被取消"，由 close 处理器用它把结果判成 aborted。 */
      let aborted = null;

      /**
       * 终止远端命令：先发 TERM，短暂宽限后**关闭通道**，并**等通道真的关掉**再返回。
       *
       * ── 为什么顺序和等待都重要（实测教训）────────────────────────────────
       * 原来这里是"发 TERM → 3 秒后才关通道 → 立刻 reject"。三个问题：
       *   ① **TERM 往往无效**：SSH 的 `signal` 请求多数 sshd 并不实现（OpenSSH 就忽略它），
       *      所以"已发送 TERM"≠"远端会停"；
       *   ② **真正起作用的是关通道**（服务端在通道关闭时对会话进程组发 SIGHUP），
       *      而把关闭推迟 3 秒，等于让远端进程多活 3 秒；
       *   ③ 取消了却**不等通道关闭就返回**，调用方会以为"已经停了"，而实际上通道还开着。
       * 所以现在：TERM 立刻发（尽力而为），宽限 `graceMs` 后就关，并且**等关闭落地**（带上限）。
       * 即便如此，"远端进程是否真的死了"仍取决于服务端 —— 见 ISSUES §12.6 的实测结论。
       */
      const terminate = () => {
        try { streamRef?.signal?.('TERM'); } catch { /* 多数服务端会忽略，尽力而为 */ }
        if (!streamRef) return Promise.resolve();
        const stream = streamRef;
        return new Promise((resolve) => {
          let done = false;
          const finishOnce = () => { if (!done) { done = true; clearTimeout(grace); clearTimeout(hard); resolve(); } };
          const grace = setTimeout(() => { try { stream.close(); } catch { finishOnce(); } }, 500);
          const hard = setTimeout(finishOnce, 3000);   // 关不掉也不能无限等
          try { stream.once?.('close', finishOnce); } catch { /* 老实现可能没有 once */ }
        });
      };

      const finish = (fn, arg) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (signal && onAbort) {
          try { signal.removeEventListener('abort', onAbort); } catch { /* 尽力而为 */ }
        }
        fn(arg);
      };

      const timer = setTimeout(() => {
        // 超时路径同样先发 TERM 再拒绝（拒绝要快，因此不在这里等通道关闭）
        terminate();
        finish(reject, Object.assign(
          new Error(`命令超时（${timeoutMs}ms）已发送 TERM：${argv.join(' ')}`),
          { code: 'timeout', argv },
        ));
      }, timeoutMs);

      // 已经中断过：立刻拒绝，连通道都不开
      if (signal?.aborted) {
        clearTimeout(timer);
        settled = true;
        reject(Object.assign(new Error(`命令在开始前已被取消：${argv.join(' ')}`), { code: 'aborted', argv }));
        return;
      }
      if (signal && typeof signal.addEventListener === 'function') {
        onAbort = () => {
          // ★ 标记为"已请求取消"，然后关通道并**等它真的关掉**。
          //
          // 为什么必须用标记、而不是直接 reject：关闭通道会让 stream 触发 `close`，
          // 而 `close` 的处理器本来会**正常 resolve**（带着被截断的输出）。
          // 我先写了"直接 reject + 异步关闭"，结果 close 先到、把结果 resolve 掉了 ——
          // 于是"取消"被报成了**成功**（实测：错误码 = (无错误)）。
          // 所以取消的语义必须由 close 处理器统一裁定：看到标记就 reject。
          aborted = Object.assign(
            new Error(`命令已被取消（${whyCancelled(signal)}）：${argv.join(' ')}`),
            { code: 'aborted', argv },
          );
          terminate();
          // 兜底：万一通道关不掉，也不能让调用方一直等（terminate 自己也有上限）
          const backstop = setTimeout(() => finish(reject, aborted), 4000);
          backstop.unref?.();
        };
        signal.addEventListener('abort', onAbort, { once: true });
      }

      session.client.exec(command, (err, stream) => {
        // 取消可能发生在"已拒绝、但 exec 回调才刚到"的窗口里：此时必须把通道关掉，
        // 否则远端命令会在一条没人持有的通道上继续跑。
        if (settled) {
          try { stream?.signal?.('TERM'); stream?.close(); } catch { /* 尽力而为 */ }
          return;
        }
        if (err) return finish(reject, err);
        streamRef = stream;

        const out = [];
        const errOut = [];
        let outLen = 0;
        let errLen = 0;

        stream.on('data', (d) => {
          if (outLen < maxBytes) { out.push(d); outLen += d.length; }
        });
        stream.stderr.on('data', (d) => {
          if (errLen < maxBytes) { errOut.push(d); errLen += d.length; }
        });
        stream.on('close', (code, signal) => {
          session.commands += 1;
          // ★ 取消的裁定点：通道关闭可能由"取消"触发，也可能由"命令正常跑完"触发。
          //   两者的 `close` 长得一模一样，唯一能区分的就是这个标记。
          if (aborted) return finish(reject, aborted);
          const stdoutBuf = Buffer.concat(out);
          const stderrBuf = Buffer.concat(errOut);
          finish(resolve, {
            exit: typeof code === 'number' ? code : null,
            signal: signal ?? null,
            truncated: outLen >= maxBytes || errLen >= maxBytes,
            stdout: binary ? stdoutBuf : stdoutBuf.toString('utf8'),
            stderr: binary ? stderrBuf : stderrBuf.toString('utf8'),
            command,
          });
        });

        if (input !== undefined) stream.end(input);
      });
    });
  }

  // ── 协从端脚本投递与 facts 采集 ─────────────────────────────────────────

  /**
   * 把引导脚本经 stdin 交给远端 `sh` 执行（`sh -s -- <args>`）。
   *
   * **这是"零安装首次接触"的关键**：不要求远端有 curl/wget/python/node，
   * 也不需要先把文件落到磁盘 —— 只要有一个 POSIX sh，就能采集 facts。
   */
  async function runAgentScript(session, args = [], opts = {}) {
    if (!agentScriptPath) throw new Error('未配置 agentScriptPath，无法投递协从端脚本');
    const script = readFileSync(agentScriptPath);
    return execOnSession(session, ['sh', '-s', '--', ...args], {
      ...opts,
      input: script,
      timeoutMs: opts.timeoutMs ?? 60000,
    });
  }

  /** 采集环境画像。 */
  async function probeFacts(target, opts = {}) {
    const session = await connect(target);
    const res = await runAgentScript(session, ['--check'], { signal: opts.signal ?? null });
    if (res.exit !== 0) {
      throw new Error(`facts 采集失败（exit ${res.exit}）：${(res.stderr || res.stdout).trim().slice(0, 400)}`);
    }
    let facts;
    try {
      facts = JSON.parse(res.stdout);
    } catch (err) {
      throw new Error(`facts 输出不是合法 JSON：${err.message}；原始输出前 200 字节：${res.stdout.slice(0, 200)}`);
    }
    if (facts?.schema !== 'vmprobe/facts/1') {
      throw new Error(`facts schema 不符：${JSON.stringify(facts?.schema)}`);
    }
    return {
      ...facts,
      transport: { mode: 'stdin-bootstrap', collectedAt: new Date().toISOString() },
    };
  }

  // ── 探测（check）────────────────────────────────────────────────────────

  /**
   * 只读探测。返回值会参与"计划新鲜度"判定，因此：
   *   · 必须带 `probed: true`，否则计划会被判为无法验证而 fail-closed；
   *   · 只放**影响决策**的字段，不放时间戳（否则计划永远过期）。
   */
  const probes = {
    async none(target, _facts, opts = {}) {
      await connect(target, opts);
      return { reachable: true };
    },
    async 'pkg.upgradable'(target, _facts, opts = {}) {
      const facts = await probeFacts(target, opts);
      return {
        count: facts.pkg?.upgradable ?? null,
        sizeBytes: null,
        securityUpgradable: facts.pkg?.securityUpgradable ?? null,
        kernelUpgradePending: facts.pkg?.kernelUpgradePending === true,
        rebootRequired: facts.pkg?.rebootRequired === true,
        distro: facts.os?.id ?? null,
        idLike: facts.os?.idLike ?? null,
      };
    },
    async 'ssh.pubkeyState'(target, _facts, opts = {}) {
      const facts = await probeFacts(target, opts);
      const session = await sessionFor(target.id);
      const key = loadIdentity(target.id);
      let installed = false;
      if (key?.publicKeyLine) {
        const blob = key.publicKeyLine.split(/\s+/)[1];
        const res = await execOnSession(session, ['sh', '-c',
          'grep -qF "$1" "${HOME}/.ssh/authorized_keys" 2>/dev/null && echo yes || echo no', 'sh', blob],
        { signal: opts.signal ?? null });
        installed = res.stdout.trim() === 'yes';
      }
      return {
        pubkeyAuth: facts.ssh?.pubkeyAuth ?? null,
        passwordAuth: facts.ssh?.passwordAuth ?? null,
        port: facts.ssh?.port ?? 22,
        serviceKeyInstalled: installed,
      };
    },
  };

  async function check(action, target, facts, opts = {}) {
    const probeName = action?.check?.probe ?? 'none';
    const impl = probes[probeName];
    if (!impl) {
      // 未实现的探测必须显式报告，不能假装成功（否则风险判定会被污染）
      return { probed: false, note: `未实现的探测：${probeName}` };
    }
    const state = await impl(target, facts, opts);
    return { probed: true, ...state };
  }

  // ── 校验（verify）──────────────────────────────────────────────────────

  /**
   * 跑一个探测并（可选地）等到满足 `expect` 为止。
   *
   * `maxWaitMs` 的存在有很实际的原因：`apt-get dist-upgrade` 返回后，
   * `apt list --upgradable` 仍可能短暂列出被 hold 的包。等一小会儿再判定，
   * 比"立即宣布没成功"更接近事实 —— 但**等到超时也绝不编造成功**。
   */
  async function runProbe({ probe, expect = null, target, facts = null, maxWaitMs = 0, signal = null } = {}) {
    const impl = probes[probe];
    if (!impl) {
      // 未实现的探测：`satisfied` 必须是**显式的 null**，而不是"这个字段不存在"。
      // 缺字段会诱使调用方写 `if (verify.satisfied)` 这类判定，把"未判定"当"否"或当"是"；
      // 契约上它只有三种取值：true / false / null。
      return {
        probed: false, probe, expect, state: null, satisfied: null,
        attempts: 0, waitedMs: 0, note: `未实现的探测：${probe}`,
      };
    }

    const started = Date.now();
    const deadline = started + Math.max(0, Number(maxWaitMs) || 0);
    let attempts = 0;
    let state = null;
    let satisfied = null;

    for (;;) {
      attempts += 1;
      state = await impl(target, facts, { signal });
      satisfied = probeSatisfies(state, expect);
      if (satisfied === true) break;
      if (Date.now() >= deadline) break;
      if (signal?.aborted) break;
      await new Promise((r) => { const t = setTimeout(r, 500); t.unref?.(); });
    }

    return {
      probed: true,
      probe,
      expect,
      state,
      satisfied,
      attempts,
      waitedMs: Date.now() - started,
      note: satisfied === null ? '未声明 expect，因此只报告状态、不做判定' : null,
    };
  }

  // ── 执行（apply）────────────────────────────────────────────────────────

  async function apply(plan, { runId, signal = null } = {}) {
    const target = await resolveTarget(plan.targetId);
    if (!target) throw new Error(`目标不存在：${plan.targetId}`);
    const session = await connect(target);

    const steps = [];
    let last = null;
    for (const argv of plan.resolvedArgv ?? []) {
      const res = await execOnSession(session, argv, {
        env: plan.env ?? null,
        timeoutMs: Math.min(plan.timeoutMs ?? commandTimeoutMs, commandTimeoutMs * 30),
        // 取消贯通到**每一条**命令：中断后不会继续跑后面的命令（避免半套变更）
        signal,
      });
      steps.push({ argv, exit: res.exit, stdout: res.stdout, stderr: res.stderr, truncated: res.truncated });
      last = res;
      if (res.exit !== 0) break; // 失败即停，不继续跑后续命令（避免半套变更）
    }

    return {
      exit: last?.exit ?? null,
      stdout: last?.stdout ?? '',
      stderr: last?.stderr ?? '',
      steps,
      runId: runId ?? null,
      targetId: plan.targetId,
      completedSteps: steps.filter((s) => s.exit === 0).length,
      totalSteps: (plan.resolvedArgv ?? []).length,
    };
  }

  // ── 文件投递 / 读取 ─────────────────────────────────────────────────────

  /**
   * 推送文件：走 exec + stdin（`cat > 文件`）。
   * 用位置参数把路径传进 `sh -c`，避免路径被二次解析。
   */
  async function pushFile(target, remotePath, content, { mode = 0o600, timeoutMs } = {}) {
    const session = await connect(target);
    const script = 'mkdir -p "$(dirname "$1")" && cat > "$1" && chmod '
      + Number(mode).toString(8) + ' -- "$1"';
    const res = await execOnSession(session, ['sh', '-c', script, 'sh', remotePath], {
      input: Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8'),
      timeoutMs: timeoutMs ?? 60000,
    });
    if (res.exit !== 0) throw new Error(`推送文件失败（${remotePath}）：${res.stderr.trim()}`);
    return { path: remotePath, bytes: Buffer.byteLength(content) };
  }

  async function pullFile(target, remotePath) {
    const session = await connect(target);
    const res = await execOnSession(session, ['sh', '-c', 'cat -- "$1"', 'sh', remotePath], { binary: true });
    if (res.exit !== 0) throw new Error(`读取文件失败（${remotePath}）：${String(res.stderr).trim()}`);
    return res.stdout;
  }

  /**
   * 另开一条**全新连接**，只带密钥（不给密码 → ssh2 只会尝试 publickey），
   * 跑一条自检命令后立即断开。
   *
   * 免密登录事务必须靠它来验证：**复用现有连接等于没验证** ——
   * 我们要证明的是"这条新路径真的能独立走通"，而不是"旧连接还活着"。
   * 它不注册进 `sessions`，因此不会干扰会话复用。
   */
  function verifyKeyLogin(target, privateKeyPem, opts = {}) {
    const { timeoutMs = connectTimeoutMs, probeCommand = ['echo', 'vmprobe-key-ok'] } = opts;
    return new Promise((resolve, reject) => {
      const client = new Client();
      let settled = false;
      const finish = (fn, arg) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { client.end(); } catch { /* 已断开 */ }
        fn(arg);
      };
      const timer = setTimeout(
        () => finish(reject, new Error(`密钥验证连接超时（${timeoutMs}ms）`)),
        timeoutMs,
      );

      client.on('ready', () => {
        client.exec(buildCommand(probeCommand), (err, stream) => {
          if (err) return finish(reject, err);
          let out = '';
          let errOut = '';
          stream.on('data', (d) => { out += d.toString(); });
          stream.stderr.on('data', (d) => { errOut += d.toString(); });
          stream.on('close', (code) => {
            if (code !== 0) {
              return finish(reject, new Error(
                `密钥连接的连接本身成功，但自检命令退出码 ${code}：${errOut.trim() || out.trim()}`,
              ));
            }
            finish(resolve, { ok: true, stdout: out.trim(), authMode: 'publickey-only' });
          });
        });
      });
      client.on('error', (err) => finish(reject, err));
      client.connect({
        host: target.hostname,
        port: target.port ?? 22,
        username: target.user,
        privateKey: privateKeyPem,
        readyTimeout: timeoutMs,
        hostHash: 'sha256',
        hostVerifier: (hexHash) => {
          const fp = `SHA256:${Buffer.from(hexHash, 'hex').toString('base64').replace(/=+$/, '')}`;
          const pinned = target.hostKey?.fingerprint ?? null;
          if (pinned && pinned !== fp) return false;
          if (!pinned && hostKeyPolicy === 'strict') return false;
          return true;
        },
      });
    });
  }

  /**
   * 用**密码**另开一条全新连接做验证（撤销免密前的"还有别的路可走"证明）。
   *
   * 密码来源：显式传入的 `password`，否则按 `target.authRef.ref` 走凭据解析 ——
   * 后者是常态（调用方只给目标，不该自己持有密码）。
   */
  async function verifyPasswordLogin(target, opts = {}) {
    const { timeoutMs = connectTimeoutMs, probeCommand = ['echo', 'vmprobe-pw-ok'] } = opts;
    const password = opts.password
      ?? (resolveCredential ? await resolveCredential(target.authRef?.ref) : undefined);
    return new Promise((resolve, reject) => {
      const client = new Client();
      let settled = false;
      const finish = (fn, arg) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { client.end(); } catch { /* 已断开 */ }
        fn(arg);
      };
      const timer = setTimeout(() => finish(reject, new Error(`密码验证连接超时（${timeoutMs}ms）`)), timeoutMs);

      if (!password) {
        finish(reject, new Error(
          `凭据 ${target.authRef?.ref ?? '(未设置)'} 无法解析，缺少可用密码`,
        ));
        return;
      }

      client.on('ready', () => {
        client.exec(buildCommand(probeCommand), (err, stream) => {
          if (err) return finish(reject, err);
          let out = '';
          stream.on('data', (d) => { out += d.toString(); });
          stream.on('close', (code) => {
            if (code !== 0) return finish(reject, new Error(`密码连接自检退出码 ${code}`));
            finish(resolve, { ok: true, stdout: out.trim(), authMode: 'password' });
          });
        });
      });
      client.on('error', (err) => finish(reject, err));
      client.connect({
        host: target.hostname,
        port: target.port ?? 22,
        username: target.user,
        password,
        readyTimeout: timeoutMs,
        hostHash: 'sha256',
        hostVerifier: (hexHash) => {
          const fp = `SHA256:${Buffer.from(hexHash, 'hex').toString('base64').replace(/=+$/, '')}`;
          const pinned = target.hostKey?.fingerprint ?? null;
          if (pinned && pinned !== fp) return false;
          if (!pinned && hostKeyPolicy === 'strict') return false;
          return true;
        },
      });
    });
  }

  /** 删除本地专用密钥（撤销免密时用）。 */
  function removeIdentity(targetId) {
    const { priv, pub } = identityPaths(targetId);
    const removed = [];
    for (const p of [priv, pub]) {
      try {
        if (existsSync(p)) { unlinkSync(p); removed.push(p); }
      } catch { /* 删不掉就如实反映在返回值里 */ }
    }
    return removed;
  }

  /**
   * 心跳：在**已有会话**上跑一条极轻的命令，测延迟并探测连接是否还活着。
   *
   * 三条刻意的行为：
   *   · **不主动建立连接** —— 心跳的职责是观察，不是连接。没有会话就如实说 `no-session`，
   *     否则"心跳"会变成偷偷拉起连接的东西，反而掩盖了"其实早就断了"。
   *   · 超时很短（默认 5s）：链路僵死要尽快暴露，而不是等到下一次真实操作才失败。
   *   · 失败即把会话标记为 `detached`，让上层状态与事实一致（不留"看起来还连着"的假象）。
   */
  async function heartbeat(targetId, { timeoutMs = 5000 } = {}) {
    const session = sessions.get(targetId);
    if (!session || session.state !== 'connected' || !session.client) {
      return { ok: false, reason: 'no-session', latencyMs: null, at: new Date().toISOString() };
    }
    const started = Date.now();
    try {
      const res = await execOnSession(session, ['echo', 'vmprobe-hb'], { timeoutMs });
      const latencyMs = Date.now() - started;
      if (res.exit !== 0) {
        session.state = 'detached';
        return {
          ok: false, reason: 'non-zero-exit', latencyMs,
          error: String(res.stderr || res.stdout).trim().slice(0, 200), at: new Date().toISOString(),
        };
      }
      return { ok: true, latencyMs, at: new Date().toISOString() };
    } catch (err) {
      // 通道失败通常意味着连接已死：把它标成 detached，别让状态停在 connected
      session.state = 'detached';
      return {
        ok: false, reason: err?.code === 'timeout' ? 'timeout' : 'error',
        latencyMs: Date.now() - started,
        error: err?.message ?? String(err), at: new Date().toISOString(),
      };
    }
  }

  /** 当前有活跃会话的目标 id 列表（心跳只对这些目标有意义）。 */
  function activeTargetIds() {
    return [...sessions.entries()]
      .filter(([, s]) => s.state === 'connected' && s.client)
      .map(([id]) => id);
  }

  // ── 状态与释放 ──────────────────────────────────────────────────────────

  function state(targetId) {
    if (targetId) return sessions.get(targetId)?.state ?? 'detached';
    const live = [...sessions.values()].filter((s) => s.state === 'connected');
    if (live.length === 1) return 'connected';
    if (live.length === 0) return 'detached';
    return 'connected';
  }

  function disconnect(targetId) {
    const s = sessions.get(targetId);
    if (s?.client) {
      try { s.client.end(); } catch { /* 忽略 */ }
    }
    sessions.delete(targetId);
  }

  function disposeAll() {
    for (const id of [...sessions.keys()]) disconnect(id);
  }

  return {
    // 引擎要求的接口
    check, apply, probeFacts, state,
    // 额外能力
    connect, exec: async (target, argv, opts) => execOnSession(await connect(target), argv, opts),
    pushFile, pullFile, runAgentScript,
    verifyKeyLogin, verifyPasswordLogin, removeIdentity,
    heartbeat, activeTargetIds,
    /** 校验用：跑探测并按 expect 判定（M2-①）。 */
    runProbe,
    disconnect, disposeAll,
    loadIdentity, createIdentity, identityPaths,
    /** 当前指纹（连接后才有值）。 */
    fingerprintOf: (targetId) => sessions.get(targetId)?.fingerprint ?? null,
    sessions,
    /** 供外部分辨两条连接是否同一条（免密事务要"另开一条"）。 */
    sessionCount: () => [...sessions.values()].filter((s) => s.state === 'connected').length,
  };
}

export { publicKeyFingerprint };
