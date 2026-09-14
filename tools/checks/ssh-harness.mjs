/**
 * 真实 SSH 测试台 —— 进程内的 ssh2 服务端，用来端到端验证传输层。
 *
 * 为什么这么做：本机没有 Linux 目标（WSL 无发行版、无 docker/podman），
 * 但**协议层可以是真的**。ssh2 自带服务端实现，于是我们能验证：
 *   真实 SSH 握手 · 主机密钥校验 · 密码认证 · publickey 认证 · exec 通道（含 stdin）· 退出码
 * exec 后端用 Git 自带的 bash（POSIX sh），因此**能真跑我们的 `agent/bootstrap.sh`**，
 * 免密登录事务里的 authorized_keys 读写也是真实文件操作。
 *
 * 诚实的边界：这里的"远端"是 Windows + MSYS 而不是 Linux。
 *   · 与发行版无关的东西（协议、认证、通道、文件、退出码）是真的；
 *   · 发行版相关的东西（apt/systemd/StrictModes）用**注入的假 os-release** 与**约定**模拟。
 * 因此它证明的是"传输层与事务逻辑正确"，而不是"在所有 Linux 上都能跑"。
 */

import { createRequire } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { publicKeyFingerprint, sshString } from '../../packages/transport/src/keys.js';

const require = createRequire(import.meta.url);
const { Server, Client, utils } = require('ssh2');

/** 找可用的 bash（Windows 上通常在 Git 安装目录里）。 */
function findBash() {
  const candidates = [
    'C:\\Program Files\\Git\\bin\\bash.exe',
    'C:\\Program Files (x86)\\Git\\bin\\bash.exe',
    '/bin/bash',
    '/usr/bin/bash',
  ];
  const found = candidates.find((p) => existsSync(p));
  if (!found) throw new Error('测试台需要 bash（Git for Windows 或 Linux 的 /bin/bash）');
  return found;
}

/** Windows 路径转成 MSYS 能用的正斜杠形式。 */
const toPosixish = (p) => p.replace(/\\/g, '/');

/**
 * Windows 路径 → **MSYS 视角**的路径（`/c/Users/...`）。
 *
 * 为什么必须做这一步：Node 的 `os.tmpdir()` 在本机返回 `/tmp`（它优先读 TMPDIR），
 * 而 MSYS 的 `/tmp` 映射到 Git 自己的临时目录 —— **两边看到的不是同一个文件夹**。
 * 结果就是 Node 写进 `C:\tmp\...`，而远端 shell 的 `$HOME` 指向 Git 的 `/tmp/...`，
 * 表现为"家目录不可写/文件写入后读不到"这种极难排查的错。
 * 所以统一用 `cygpath -u` 换算，保证 Node 与 bash 面对的是同一份文件。
 */
function msysPath(winPath) {
  if (process.platform !== 'win32') return winPath;
  try {
    return execFileSync('cygpath', ['-u', winPath], { encoding: 'utf8' }).trim();
  } catch {
    // 兜底：手工转成 /c/... 形式
    return winPath.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_m, d) => `/${d.toLowerCase()}`);
  }
}

/**
 * 启动测试台。
 *
 * @param {object} [options]
 * @param {string} [options.password] 密码认证口令
 * @param {string} [options.username]
 * @param {object} [options.osRelease] 注入给 bootstrap.sh 的 os-release 内容（模拟发行版）
 * @param {boolean} [options.rejectPasswordAuth] 是否拒绝密码认证（用于验证"只允许公钥"）
 * @param {string[]} [options.initialAuthorizedKeys] 预置的 authorized_keys 行
 */
export async function startHarness(options = {}) {
  const {
    password = 'secret-pw',
    username = 'ops',
    osRelease = 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\nPRETTY_NAME="Ubuntu 26.04 LTS"\n',
    initialAuthorizedKeys = [],
    bash = findBash(),
  } = options;

  // ── "远端根"：HOME 指向它，authorized_keys 与文件操作都落在这里 ──
  // 刻意建在**项目目录内**（而不是 os.tmpdir()），避免上面说过的 /tmp 视角分裂；
  // 同时用 msysPath() 换算成 bash 看得懂的路径。
  const baseDir = options.rootBase ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const root = mkdtempSync(join(baseDir, '.harness-remote-'));
  const home = join(root, 'home');
  mkdirSync(join(home, '.ssh'), { recursive: true });
  // 兜底清理：`stop()` 是正常路径，但**测试中途抛错/被中断**时它不会被调用，
  // 于是测试台会在项目目录里留下 `.harness-remote-*` 残骸（实测攒了 10 个）。
  // 正常退出时再删一次是无害的（force + 忽略错误）。
  const cleanup = () => { try { rmSync(root, { recursive: true, force: true }); } catch { /* 忽略 */ } };
  process.once('exit', cleanup);
  process.once('SIGINT', () => { cleanup(); process.exit(130); });
  process.once('SIGTERM', () => { cleanup(); process.exit(143); });
  const osReleasePath = join(root, 'os-release');
  writeFileSync(osReleasePath, osRelease, 'utf8');
  const akPath = join(home, '.ssh', 'authorized_keys');
  if (initialAuthorizedKeys.length) writeFileSync(akPath, `${initialAuthorizedKeys.join('\n')}\n`, 'utf8');

  const env = {
    ...process.env,
    // ★ 环境变量给 **bash** 用 → MSYS 形式（/c/Users/...）
    HOME: msysPath(home),
    USER: username,
    LOGNAME: username,
    VMPROBE_OS_RELEASE: msysPath(osReleasePath),
    PATH: `${dirname(bash)};${process.env.PATH}`,
  };

  // ── 主机密钥（RSA，因为 ssh2 服务端不接受 PKCS8 ed25519）──
  const hostKeyPem = generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ format: 'pem', type: 'pkcs1' }).toString();
  // 独立算出主机指纹：直接把公钥 blob 拿出来算 SHA256 —— 供测试与客户端观测值交叉验证
  const hostParsed = utils.parseKey(hostKeyPem);
  const hostFingerprint = publicKeyFingerprint(hostParsed.getPublicSSH());

  const stats = { connections: 0, authAttempts: [], execs: [], clientErrors: [], rejected: 0 };
  /** 跟踪已建立的客户端连接 —— `server.close()` 只停止接受新连接、**不会断开已有连接**，
   *  所以不主动 end() 它们的话 stop() 会永远等下去（踩过：心跳测试直接挂住）。 */
  const liveClients = new Set();

  /** 读当前 authorized_keys 里的公钥 blob 集合。 */
  function authorizedBlobs() {
    if (!existsSync(akPath)) return new Set();
    return new Set(
      readFileSync(akPath, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean)
        .map((l) => l.split(/\s+/)[1]).filter(Boolean),
    );
  }

  const server = new Server({ hostKeys: [hostKeyPem] }, (client) => {
    stats.connections += 1;
    liveClients.add(client);
    client.on('close', () => liveClients.delete(client));
    // 必须有 error 监听：客户端在握手/认证中途断开（例如它自己拒绝了主机密钥）时，
    // 服务端 Client 会 emit 'error'；没人接就会变成 unhandled error 把整个测试进程打崩。
    client.on('error', (err) => {
      stats.clientErrors.push(err?.code ?? err?.message ?? String(err));
    });
    client.on('authentication', (ctx) => {
      stats.authAttempts.push(ctx.method);
      if (ctx.method === 'password') {
        if (options.rejectPasswordAuth) return ctx.reject(['publickey']);
        if (ctx.username === username && ctx.password === password) return ctx.accept();
        return ctx.reject(['password', 'publickey']);
      }
      if (ctx.method === 'publickey') {
        const wanted = authorizedBlobs();
        const offered = Buffer.from(ctx.key.data).toString('base64');
        if (ctx.username === username && wanted.has(offered)) return ctx.accept();
        return ctx.reject(['publickey']);
      }
      return ctx.reject(['password', 'publickey']);
    });

    client.on('ready', () => {
      client.on('session', (accept) => {
        const session = accept();
        session.on('exec', (acceptExec, _reject, info) => {
          const stream = acceptExec();
          stats.execs.push(info.command);

          const child = spawn(bash, ['-c', info.command], {
            // ★ cwd 给 **Node** 用 → 必须是 Windows 形式；给 /c/... 会 ENOENT
            cwd: home, env, windowsHide: true,
          });

          /**
           * ★ 通道关闭 → **杀掉子进程**（忠实模拟 sshd 的行为）。
           *
           * 真实的 sshd 在通道关闭时会对该会话的进程组发 SIGHUP，远端命令随之结束 ——
           * 这正是客户端侧"取消 = 关闭通道"能生效的原因。
           *
           * 原来的测试台**没有**这一步：通道关了，spawn 出来的 bash 照样把命令跑完。
           * 后果不是"测试没覆盖"，而是**测试给出了错误结论**：
           * 我据此写过"取消后远端命令不再继续"，而实测是命令**跑完了**（marker 文件照样生成）。
           * 换句话说：光靠客户端关通道不足以让这个测试台停手，缺的是服务端那一半。
           * 补上这一步之后，"关闭通道是否真的能阻止远端命令"才有了可验证的语义，
           * 同时也把边界标清楚：**这验证的是"客户端关通道 + 服务端按 sshd 语义处理"这一组合**，
           * 真实 OpenSSH 上同样成立，但 TERM 请求（多数 sshd 忽略）不能作为依靠。
           */
          const killChild = () => {
            try {
              if (!child.killed && child.exitCode === null) {
                // Windows 上没有真正的进程组信号：用 taskkill /T 连带子进程一起收掉
                if (process.platform === 'win32') {
                  try { execFileSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' }); }
                  catch { try { child.kill('SIGKILL'); } catch { /* 已经退出 */ } }
                } else {
                  try { process.kill(-child.pid, 'SIGHUP'); }
                  catch { try { child.kill('SIGHUP'); } catch { /* 已经退出 */ } }
                }
              }
            } catch { /* 尽力而为：进程可能刚好自己结束了 */ }
          };
          // 客户端的 stdin 原样喂给子进程（协从端脚本就是这样投递的）
          stream.on('data', (d) => child.stdin.write(d));
          stream.on('end', () => child.stdin.end());
          stream.on('close', () => {
            try { child.stdin.end(); } catch { /* 已关闭 */ }
            killChild();
          });
          child.stdout.on('data', (d) => stream.write(d));
          child.stderr.on('data', (d) => stream.stderr.write(d));
          child.on('close', (code) => {
            stream.exit(code ?? 1);
            stream.end();
          });
          child.on('error', (err) => {
            stream.stderr.write(`harness spawn error: ${err.message}\n`);
            stream.exit(127);
            stream.end();
          });
        });
      });
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  return {
    port,
    host: '127.0.0.1',
    username,
    password,
    root,
    /** bash 视角的家目录（事务与 exec 都用它） */
    home: msysPath(home),
    /** Node 视角的家目录（断言与清理用它） */
    homeWin: home,
    rootWin: root,
    akPath: msysPath(akPath),
    akPathWin: akPath,
    hostFingerprint,
    stats,
    authorizedBlobs,
    /** 直接读远端 authorized_keys 内容（供断言）。 */
    readAuthorizedKeys: () => (existsSync(akPath) ? readFileSync(akPath, 'utf8') : ''),
    /** 直接写（测试用；正常路径应经 exec 追加）。 */
    writeAuthorizedKeys: (text) => writeFileSync(akPath, text, 'utf8'),
    async stop() {
      // 先主动断开所有仍然活着的客户端，否则 server.close() 会一直等它们（见 liveClients 注释）
      for (const c of [...liveClients]) {
        try { c.end(); } catch { /* 已断开 */ }
      }
      await new Promise((resolve) => server.close(resolve));
      try { rmSync(root, { recursive: true, force: true }); } catch { /* 忽略 */ }
    },
    /** 强制切断所有连接（模拟"远端消失"），但保留服务端继续监听。 */
    dropConnections() {
      const n = liveClients.size;
      for (const c of [...liveClients]) {
        try { c.end(); } catch { /* 已断开 */ }
      }
      return n;
    },
  };
}

/** 造一个 Target 记录（指向测试台）。 */
export function harnessTarget(harness, overrides = {}) {
  return {
    id: 't_harness',
    label: 'harness',
    hostname: harness.host,
    port: harness.port,
    user: harness.username,
    authRef: { kind: 'password', ref: 'VMPROBE_HARNESS_PASSWORD' },
    hostKey: { algo: 'ssh-rsa', fingerprint: null, trust: 'unverified', pinnedAt: null },
    transport: 'embedded',
    tags: [],
    agent: null,
    lastSeenAt: null,
    ...overrides,
  };
}

/**
 * **喂给 `engine.addTarget()` 的扁平输入**（与 `harnessTarget()` 刻意区分开）。
 *
 * `engine.addTarget` 走 `makeTarget`，它要的是 `{ authRef: '引用字符串', authKind }`；
 * 而 `harnessTarget()` 产出的是**已完成规范化**的目标形状（`authRef: { kind, ref }`）。
 * 两者混用会把 ref 嵌套成对象 —— 在"忽略参数"的凭据解析器下照样能跑，
 * 于是错误潜伏到某个严格解析器上才以"凭据 [object Object] 尚未配置"的形式暴露。
 * 所以这里提供两个明确命名的入口，谁用哪个一目了然。
 */
export function harnessTargetInput(harness, overrides = {}) {
  return {
    id: 't_harness',
    label: 'harness',
    hostname: harness.host,
    port: harness.port,
    user: harness.username,
    authRef: 'VMPROBE_HARNESS_PASSWORD',
    authKind: 'password',
    tags: [],
    ...overrides,
  };
}

export { sshString, Client };
