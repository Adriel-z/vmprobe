/**
 * 运行日志（`logs/run.jsonl`）的测试（技术债 #13）。
 *
 * 这里最重要的是一条**回归**：`maxRunLogBytes` 一旦缺失，`size <= undefined` 恒为 false，
 * 于是**每写一条就轮转一次** —— 症状是"运行日志永远只有一行"，看起来像"日志功能没生效"，
 * 实际上是每写一条就把上一条挪走了。这个 bug 我写完就撞上了，所以必须有测试盯着。
 */

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { createEngine } from '../src/engine.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'vmprobe-runlog-'));

/** 读运行日志（每行一个 JSON 对象）。 */
function readRunLog(dir) {
  const p = join(dir, 'logs', 'run.jsonl');
  if (!existsSync(p)) return [];
  return readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

test('运行日志逐条落盘，带 level，且**不含哈希链字段**（它不是审计）', () => {
  const dir = tmp();
  try {
    const engine = createEngine({ dir, transport: null, config: { dailyReport: false } });
    engine.record('action.run', { runId: 'r_1', exit: 0 });
    engine.record('transport.heartbeat.failed', { targetId: 't1' });
    engine.record('config.warning', { warning: '某键非法' });
    engine.record('report.skipped', { reason: 'no-facts-source' });

    const lines = readRunLog(dir);
    assert.ok(lines.length >= 4, `应有至少 4 行，实际 ${lines.length}`);
    assert.ok(lines.every((l) => typeof l.level === 'string'), '每行都要有 level');
    assert.ok(lines.every((l) => !('prev' in l) && !('hash' in l)), '链字段不得混进运行日志');
    assert.ok(lines.every((l) => typeof l.ts === 'string'), '每行都要有时间戳');

    const byEvent = Object.fromEntries(lines.map((l) => [l.event, l.level]));
    assert.equal(byEvent['transport.heartbeat.failed'], 'error', '失败类事件应为 error');
    assert.equal(byEvent['config.warning'], 'warn');
    assert.equal(byEvent['report.skipped'], 'warn');
    assert.equal(byEvent['action.run'], 'info');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('★ 回归：默认阈值下**不得**每次写入都轮转（日志要能累积）', () => {
  const dir = tmp();
  try {
    const engine = createEngine({ dir, transport: null, config: { dailyReport: false } });
    for (let i = 0; i < 20; i += 1) engine.record('action.run', { runId: `r_${i}`, exit: 0 });
    const lines = readRunLog(dir);
    assert.ok(lines.length >= 20, `写入 20 条后应有 ≥20 行，实际 ${lines.length}（每次轮转就会只剩 1 行）`);
    assert.ok(!existsSync(join(dir, 'logs', 'run.0001.jsonl')), '不该产生轮转文件');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('超过阈值时才轮转，且只保留一代历史', () => {
  const dir = tmp();
  try {
    // 阈值调到很小，方便触发
    const engine = createEngine({
      dir, transport: null, config: { dailyReport: false, maxRunLogBytes: 400 },
    });
    for (let i = 0; i < 12; i += 1) engine.record('action.run', { runId: `r_${i}`, note: 'x'.repeat(20) });
    assert.ok(existsSync(join(dir, 'logs', 'run.0001.jsonl')), '超过阈值后应出现轮转文件');
    const current = readRunLog(dir);
    const rotated = readFileSync(join(dir, 'logs', 'run.0001.jsonl'), 'utf8').trim().split('\n').filter(Boolean);
    assert.ok(current.length >= 1 && rotated.length >= 1, '轮转后当前文件与历史文件都应有内容');
    assert.ok(current.length + rotated.length <= 14, '轮转只保留一代，不该无限堆积');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('runLog=false 时完全不写运行日志（但审计照写）', () => {
  const dir = tmp();
  try {
    const engine = createEngine({ dir, transport: null, config: { dailyReport: false, runLog: false } });
    engine.record('action.run', { runId: 'r_1' });
    assert.equal(existsSync(join(dir, 'logs', 'run.jsonl')), false, '关闭后不该有运行日志');
    assert.ok(existsSync(join(dir, 'logs', 'audit.jsonl')), '审计必须照常记录（它是证据）');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
