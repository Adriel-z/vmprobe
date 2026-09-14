/**
 * 统一脱敏单测 —— 对应推演发现 I8。
 *
 * 关键性质：
 *   · 秘密被替换，**非秘密文本原样保留**（否则脱敏会毁掉日志可用性）；
 *   · 够幂等（重复脱敏结果不变，不会层层叠标记）；
 *   · 保留"此处曾被脱敏"的事实（redactedPaths），既看不到秘密，又知道秘密经过。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createRedactor, redactDeep, redactText } from '../src/redact.js';
import { isSecretKeyName } from '../src/store.js';

test('脱敏 PEM 私钥整块', () => {
  const pem = 'here\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\ntail';
  const out = redactText(pem);
  assert.match(out, /\[REDACTED:private-key\]/);
  assert.ok(!out.includes('AAAA'), '私钥内容不得残留');
  assert.match(out, /^here/);
  assert.match(out, /tail$/);
});

test('脱敏 key=value 形式的凭据', () => {
  assert.match(redactText('password=hunter2'), /password=\[REDACTED:key-value\]/);
  assert.match(redactText('passwd: abc'), /passwd: \[REDACTED:key-value\]/);
  assert.match(redactText('{"token": "abc123"}'), /"token": "\[REDACTED:key-value\]"/);
  assert.match(redactText('api_key=sk-live-xyz'), /\[REDACTED:key-value\]/);
  assert.match(redactText('export APIKEY=zzz'), /\[REDACTED:key-value\]/);
});

test('JSON 形式的键值脱敏后仍是合法 JSON（保留引号风格）', () => {
  const out = redactText('{"token": "abc123", "ok": true}');
  assert.deepEqual(JSON.parse(out), { token: '[REDACTED:key-value]', ok: true });
});

test('覆盖常见复合名（access_token / refresh_token / client_secret / private_key）', () => {
  const out = redactText('refresh_token=rt_123 client_secret=cs_456 private_key=/tmp/k');
  assert.ok(!out.includes('rt_123'));
  assert.ok(!out.includes('cs_456'));
  assert.ok(!out.includes('/tmp/k'));
  assert.equal((out.match(/\[REDACTED:key-value\]/g) ?? []).length, 3);

  const nest = redactText('{"nested": {"access_token": "AAA", "sessionToken": "BBB"}}');
  assert.ok(!nest.includes('AAA'));
  assert.ok(!nest.includes('BBB'));
});

test('不误伤长标识符内部的字样（mypassword 不是凭据键名）', () => {
  assert.equal(redactText('mypassword=nope'), 'mypassword=nope');
  assert.equal(redactText('{"taskId": "t_1"}'), '{"taskId": "t_1"}');
});

test('脱敏 HTTP Bearer 头（日志转储请求头是常见泄漏路径）', () => {
  const out = redactText('Authorization: Bearer abcdefghijklmnop');
  assert.match(out, /Bearer \[REDACTED:bearer-token\]/);
  assert.ok(!out.includes('abcdefghijklmnop'));
});

test('脱敏命令行里的凭据（-u user:pass）', () => {
  const out = redactText('curl -u admin:s3cr3t https://x/y');
  assert.match(out, /\[REDACTED:cli-credentials\]/);
  assert.ok(!out.includes('s3cr3t'));
  // 没有冒号的普通参数不该被误伤
  assert.equal(redactText('curl -u root https://x/y'), 'curl -u root https://x/y');
});

test('脱敏 URL 内嵌凭据，但保留 scheme 与主机', () => {
  const out = redactText('git clone https://alice:s3cr3t@example.com/repo.git');
  assert.match(out, /https:\/\/\[REDACTED:url-credentials\]@example\.com\/repo\.git/);
  assert.ok(!out.includes('s3cr3t'));
});

test('脱敏 JWT 与 AWS access key', () => {
  assert.match(redactText('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk'), /\[REDACTED:jwt\]/);
  assert.match(redactText('key=AKIAIOSFODNN7EXAMPLE'), /\[REDACTED:aws-access-key\]/);
});

test('运行时登记的秘密值被字面替换（认证切换场景）', () => {
  const out = redactText('connecting with p@ssw0rd-123 now', { registered: ['p@ssw0rd-123'] });
  assert.match(out, /\[REDACTED:registered\]/);
  assert.ok(!out.includes('p@ssw0rd-123'));
  // 太短的值不登记（否则会把正常文本打成筛子）
  assert.equal(redactText('abc def', { registered: ['abc'] }), 'abc def');
});

test('非秘密文本原样保留', () => {
  const s = 'apt-get -y dist-upgrade 完成，12 个包已更新，退出码 0';
  assert.equal(redactText(s), s);
  assert.equal(redactText(''), '');
  assert.equal(redactText(null), null);
});

test('幂等：重复脱敏不再变化', () => {
  const once = redactText('password=hunter2 token: abc.def.ghi');
  assert.equal(redactText(once), once);
  const deepOnce = redactDeep({ token: 'x', note: 'password=hunter2' });
  const twice = redactDeep(deepOnce.value);
  assert.deepEqual(twice.value, deepOnce.value, '第二轮不应再产生新的 redacted 路径');
});

test('redactDeep：秘密键名整体替换，并记录路径', () => {
  const { value, redactedPaths } = redactDeep({
    targetId: 't_vm',
    authRef: { kind: 'password', ref: 'vault://x' },
    password: 'hunter2',
    nested: { accessKey: 'AKIA...' },
  });
  assert.equal(value.password, '[REDACTED:key-name]');
  assert.equal(value.nested.accessKey, '[REDACTED:key-name]');
  assert.deepEqual(redactedPaths.sort(), ['$.nested.accessKey#key', '$.password#key']);
  // 合法的元数据不受影响
  assert.equal(value.authRef.kind, 'password');
  assert.equal(value.targetId, 't_vm');
});

test('redactDeep：值里的模式命中也会被记录', () => {
  // 命令行形态的凭据（不在 URL 里）—— 单测发现这是原实现漏掉的真实泄漏路径
  const { value, redactedPaths } = redactDeep({ cmd: 'curl -u user:pw https://x/y' });
  assert.match(value.cmd, /\[REDACTED:cli-credentials\]/);
  assert.ok(!value.cmd.includes('user:pw'), '用户名口令组合不得残留');
  assert.deepEqual(redactedPaths, ['$.cmd']);
});

test('redactDeep：数组下标进路径，且保持结构', () => {
  const { value, redactedPaths } = redactDeep([{ ok: 1 }, { secret: 'x' }]);
  assert.equal(Array.isArray(value), true);
  assert.equal(value.length, 2);
  assert.equal(value[1].secret, '[REDACTED:key-name]');
  assert.deepEqual(redactedPaths, ['$[1].secret#key']);
});

test('createRedactor：登记 → 用完清空', () => {
  const r = createRedactor();
  assert.equal(r.size, 0);
  r.add('s3cr3t-value');
  r.add('xy'); // 太短，忽略
  assert.equal(r.size, 1);
  assert.match(r.text('pw=s3cr3t-value'), /\[REDACTED:registered\]/);
  r.clear();
  assert.equal(r.size, 0);
  assert.equal(r.text('pw=s3cr3t-value'), 'pw=s3cr3t-value');
});

test('createRedactor.error：保留名称与 code，但消息已脱敏', () => {
  const r = createRedactor();
  r.add('sup3rsecret');
  const src = Object.assign(new Error('auth failed: sup3rsecret'), { code: 'AUTH_FAIL' });
  const out = r.error(src);
  assert.ok(out instanceof Error);
  assert.equal(out.code, 'AUTH_FAIL');
  assert.ok(!out.message.includes('sup3rsecret'));
  assert.match(out.message, /\[REDACTED:registered\]/);
});

test('键名判定与 store 的写入拒绝共用同一实现（不会漂移）', () => {
  for (const k of ['password', 'secretKey', 'accessKey', 'bearer', 'sessionToken', 'privateKey', 'apiKey']) {
    assert.equal(isSecretKeyName(k), true, `${k} 应被判为秘密载体`);
  }
  for (const k of ['passwordAuth', 'pubkeyAuth', 'authKind', 'authRef', 'privateKeyPath', 'hostKey', 'targetId']) {
    assert.equal(isSecretKeyName(k), false, `${k} 是合法元数据，不应被判为秘密`);
  }
});
