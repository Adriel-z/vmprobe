/**
 * 运行记录（`runs/`）与 runId 安全性的单元测试（M2-②）。
 *
 * 这里锁的是三件容易出事的事：
 *   ① runId 会变成**文件名**，必须挡住路径穿越（F6 同类）；
 *   ② 输出必须**先脱敏再落盘**；
 *   ③ 超限要**截断并标注**，不能悄悄丢尾巴。
 */

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  assertSafeRunId, newRunId, persistRun, renderRun, runPath, verifyRunSeal, RunIdError,
} from '../src/runs.js';
import { createRedactor } from '../../core/src/redact.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'vmprobe-runs-'));

test('newRunId 形状：r_ + UTC 紧凑时间 + 后缀，且字典序即时间序', () => {
  const a = newRunId(new Date('2026-09-14T10:00:00Z'), () => 0.1);
  const b = newRunId(new Date('2026-09-14T11:00:00Z'), () => 0.1);
  assert.match(a, /^r_20260914T100000_[0-9a-f]{6}$/);
  assert.ok(a < b, '更早的时间应排在前（字典序 = 时间序）');
  assert.doesNotThrow(() => assertSafeRunId(a));
});

test('★ runId 是文件名，必须挡住路径穿越', () => {
  for (const bad of ['../../etc/passwd', 'r_a/b', 'r_a.b', 'r_', 'a_b', 'r_' + 'x'.repeat(80), '', null, 42]) {
    assert.throws(() => assertSafeRunId(bad), RunIdError, `应拒绝 ${JSON.stringify(bad)}`);
  }
  assert.throws(() => runPath('/tmp', '../evil'), RunIdError);
});

test('persistRun 落盘并给出 sha256 与字节数；verifyRunSeal 能检出事后篡改', () => {
  const root = tmp();
  try {
    const runId = 'r_20260914T100000_abc123';
    const ref = persistRun({ root, runId, text: 'hello\nworld\n' });
    assert.equal(ref.relPath, `runs/${runId}.log`);
    assert.equal(ref.bytes, readFileSync(ref.path, 'utf8').length);
    assert.equal(typeof ref.sha256, 'string');
    assert.equal(ref.sha256.length, 64);
    assert.equal(ref.truncated, false);

    assert.deepEqual(verifyRunSeal({ root, runId, sha256: ref.sha256 }), { ok: true, sha256: ref.sha256 });

    // 事后改一个字符 → 必须检出
    writeFileSync(ref.path, 'hello\nWORLD\n', 'utf8');
    const bad = verifyRunSeal({ root, runId, sha256: ref.sha256 });
    assert.equal(bad.ok, false);
    assert.match(bad.reason, /摘要不符/);

    // 文件被删
    rmSync(ref.path);
    assert.equal(verifyRunSeal({ root, runId, sha256: ref.sha256 }).ok, false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('超过上限时截断，并**明确标注**（不是悄悄丢尾巴）', () => {
  const root = tmp();
  try {
    const ref = persistRun({ root, runId: 'r_20260914T100000_abc124', text: 'x'.repeat(5000), maxBytes: 1000 });
    assert.equal(ref.truncated, true);
    const body = readFileSync(ref.path, 'utf8');
    assert.match(body, /已截断/);
    assert.ok(ref.bytes < 2000, `截断后不应超过上限太多，实际 ${ref.bytes}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('★ 落盘内容必须脱敏：命令输出里的秘密不得进入 runs/*.log', () => {
  const root = tmp();
  try {
    const redactor = createRedactor();
    redactor.add('hunter2-SECRET');
    const plan = {
      actionId: 'system.update', actionVersion: 2, side: 'agent', targetId: 't1', targetLabel: 'vm',
      risk: 'R1', distroKey: 'debian', params: {}, resolvedArgv: [['apt-get', '-y', 'dist-upgrade']],
    };
    const text = renderRun({
      runId: 'r_20260914T100000_abc125',
      plan,
      result: { exit: 0, steps: [{ argv: ['apt-get'], exit: 0, stdout: 'password=hunter2-SECRET', stderr: '' }] },
      startedAt: 'a', finishedAt: 'b', exit: 0, redactor,
    });
    assert.ok(!text.includes('hunter2-SECRET'), '明文秘密不得出现在运行记录里');
    assert.match(text, /REDACTED|已脱敏|\*\*\*/i);
    const ref = persistRun({ root, runId: 'r_20260914T100000_abc125', text });
    assert.ok(!readFileSync(ref.path, 'utf8').includes('hunter2-SECRET'));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('renderRun 把校验结论如实写出来（三种结论各说各话）', () => {
  const plan = { actionId: 'a.b', side: 'agent', targetId: 't', risk: 'R1', resolvedArgv: [] };

  const ok = renderRun({ runId: 'r_x', plan, verify: { probe: 'pkg.upgradable', expect: { count: 0 }, state: { count: 0 }, satisfied: true, attempts: 2, waitedMs: 700 } });
  assert.match(ok, /达到目标态/);
  assert.match(ok, /2 次 \/ 700ms/);

  const bad = renderRun({ runId: 'r_x', plan, verify: { probe: 'pkg.upgradable', expect: { count: 0 }, state: { count: 3 }, satisfied: false, attempts: 1, waitedMs: 10 } });
  assert.match(bad, /★ 未达到目标态/);

  const unknown = renderRun({ runId: 'r_x', plan, verify: { probe: 'pkg.upgradable', satisfied: null, note: '未声明 expect' } });
  assert.match(unknown, /未判定/);

  const skipped = renderRun({ runId: 'r_x', plan, verify: { skipped: true, reason: 'dryRun 预演未产生变更，不做目标态校验' } });
  assert.match(skipped, /已跳过/);
  assert.match(skipped, /dryRun/);
});

test('renderRun 在失败时也留下记录（失败更需要复盘）', () => {
  const plan = { actionId: 'a.b', side: 'agent', targetId: 't', risk: 'R1', resolvedArgv: [['false']] };
  const text = renderRun({ runId: 'r_x', plan, error: '远端命令失败：exit 1', exit: 1 });
  assert.match(text, /错误/);
  assert.match(text, /exit 1/);
});
