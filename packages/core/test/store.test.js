/**
 * 存储层单测 —— 重点是「凭据不落地」这条被代码强制的机制。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { assertSecretFree, makeTarget, openStore } from '../src/store.js';

test('拒密：键名为 password / passphrase / privateKey 等一律抛错', () => {
  assert.throws(() => assertSecretFree({ password: 'hunter2' }), /敏感字段 "password"/);
  assert.throws(() => assertSecretFree({ nested: { passphrase: 'x' } }), /敏感字段 "passphrase"/);
  assert.throws(() => assertSecretFree({ a: [{ privateKey: 'k' }] }), /敏感字段 "privateKey"/);
  assert.throws(() => assertSecretFree({ ssh: { private_key: 'k' } }), /敏感字段 "private_key"/);
  assert.throws(() => assertSecretFree({ apiKey: 'sk-x' }), /敏感字段 "apiKey"/);
  assert.throws(() => assertSecretFree({ access_token: 't' }), /敏感字段 "access_token"/);
});

test('拒密：值里出现 PEM 私钥内容也抛错', () => {
  const pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----';
  assert.throws(() => assertSecretFree({ blob: pem }), /疑似私钥内容/);
});

test('允许 authRef 引用（引用不是凭据）', () => {
  assert.doesNotThrow(() =>
    assertSecretFree({ authRef: { kind: 'password', ref: 'vault://vm-a/login' } }),
  );
});

test('makeTarget 产出无凭据记录，且必须给 authRef', () => {
  const t = makeTarget({
    id: 't_a1b2',
    label: 'vm-a',
    hostname: '10.0.0.5',
    user: 'ops',
    authRef: 'vault://vm-a/login',
    fingerprint: 'SHA256:abc',
    tags: ['staging'],
  });
  assert.equal(t.hostKey.trust, 'pinned');
  assert.equal(t.hostKey.fingerprint, 'SHA256:abc');
  assert.equal(t.port, 22);
  assert.equal(t.transport, 'embedded');
  assert.deepEqual(t.tags, ['staging']);

  assert.throws(() => makeTarget({ id: 'x', hostname: 'h', user: 'u' }), /authRef/);

  // 未提供指纹 → 未固定（首次连接时须经审批再固定）
  const unpinned = makeTarget({ id: 't_c', hostname: 'h', user: 'u', authRef: 'vault://c' });
  assert.equal(unpinned.hostKey.trust, 'unverified');
  assert.equal(unpinned.hostKey.fingerprint, null);
});

test('openStore：原子写 + 读回一致，并在写路径上拒密', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vmprobe-store-'));
  try {
    const store = await openStore({ dir });

    // 空态默认值
    const empty = await store.readTargets();
    assert.deepEqual(empty.targets, []);

    const t = makeTarget({ id: 't_1', hostname: '10.0.0.5', user: 'ops', authRef: 'vault://a' });
    await store.writeTargets({ targets: [t] });
    const back = await store.readTargets();
    assert.equal(back.schema, 'vmprobe/targets/1');
    assert.equal(back.targets[0].id, 't_1');

    // 磁盘上确实不含任何凭据字段。
    // 注意：只检查「键」形式 —— authRef.kind 的**值** "password" 是合法元数据，
    // 它描述认证方式，不是凭据本身。（守卫 assertSecretFree 同样只查键名。）
    const raw = await readFile(store.paths.targets, 'utf8');
    assert.ok(!/"password"\s*:/i.test(raw), 'targets.json 不应出现 password 键');
    assert.ok(!/PRIVATE KEY/.test(raw), 'targets.json 不应出现私钥内容');
    assert.match(raw, /vault:\/\/a/, '应保留 authRef 引用');
    assert.match(raw, /"kind":\s*"password"/, '认证方式元数据应保留');

    // 写入带密码的对象必须被拒（且不落盘）
    await assert.rejects(
      () => store.writeTargets({ targets: [{ id: 't_2', password: 'oops' }] }),
      /敏感字段/,
    );
    const after = await store.readTargets();
    assert.equal(after.targets.length, 1, '被拒的写入不应改动已有数据');

    // 临时文件不残留
    const { readdir } = await import('node:fs/promises');
    const files = await readdir(dir);
    assert.ok(!files.some((f) => f.includes('.tmp-')), `不应残留临时文件: ${files.join(',')}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
