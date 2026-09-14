/**
 * @vmprobe/transport —— 传输层统一出口。
 *
 * 目前只有 SSH 后端（ssh2）。接口是本项目与"远端"之间的唯一缝隙：
 *   `check(action, target, facts)` 只读探测（计划新鲜度的输入）
 *   `probeFacts(target)`           采集环境画像
 *   `apply(plan, { runId })`       按计划执行
 *   `state(targetId?)`             连接状态
 * 另有一组能力供 controller 侧动作与测试使用：
 *   `connect / exec / pushFile / pullFile / runAgentScript / loadIdentity / createIdentity`
 */

export {
  createSshTransport,
  shQuote,
  buildCommand,
  HostKeyMismatchError,
  HostKeyUnknownError,
} from './ssh.js';

export {
  generateKeypair,
  opensshPublicKeyLine,
  opensshPrivateKeyFile,
  publicKeyFingerprint,
  parsePublicKeyLine,
  ed25519PublicBlob,
} from './keys.js';
