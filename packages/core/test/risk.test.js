/**
 * 风险策略单测 —— 覆盖用户的明确决策（R0/R1 免弹、R2/R3 弹）与 fail-closed 行为。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Risk, decideApproval, maxRisk, buildApprovalReason, DEFAULT_POLICY } from '../src/risk.js';

test('R0/R1 免弹，但仍写审计', () => {
  for (const risk of [Risk.R0, Risk.R1]) {
    const d = decideApproval({ risk, target: { label: 'vm-a' } });
    assert.equal(d.requiresApproval, false, `${risk} 不应弹窗`);
    assert.equal(d.audit, true, `${risk} 必须留痕`);
    assert.equal(d.blocked, false);
    assert.equal(d.approvalReason, '', `${risk} 免弹时不应产生审批文案`);
  }
});

test('R2/R3 必须审批', () => {
  for (const risk of [Risk.R2, Risk.R3]) {
    const d = decideApproval({ risk, target: { label: 'vm-a' } });
    assert.equal(d.requiresApproval, true, `${risk} 必须弹窗`);
    assert.match(d.approvalReason, /风险级 R[23]/);
  }
});

test('仅 R3 及以上要求复述主机名', () => {
  assert.equal(decideApproval({ risk: Risk.R2 }).requireEchoHostname, false);
  assert.equal(decideApproval({ risk: Risk.R3 }).requireEchoHostname, true);
});

test('prod 标签把 R1 提升为 R2（只升不降）', () => {
  const d = decideApproval({ risk: Risk.R1, target: { tags: ['prod'] } });
  assert.equal(d.effectiveRisk, Risk.R2);
  assert.equal(d.requiresApproval, true);
  assert.ok(d.escalatedBy.some((s) => s.includes('prod')));

  // R3 不会被 prod 规则降级
  const d3 = decideApproval({ risk: Risk.R3, target: { tags: ['prod'] } });
  assert.equal(d3.effectiveRisk, Risk.R3);
});

test('内核升级 / 需重启 会把 R1 提权到 R2 —— 模型无法自我降级', () => {
  const d = decideApproval({
    risk: Risk.R1,
    target: { label: 'vm-a' },
    escalate: { kernelUpgradePending: true },
  });
  assert.equal(d.effectiveRisk, Risk.R2);
  assert.equal(d.requiresApproval, true);
  assert.deepEqual(d.escalatedBy, ['kernelUpgradePending→R2']);
});

test('审批策略 never 时，需审批的动作 fail-closed 被阻断（不是放行）', () => {
  const d = decideApproval({ risk: Risk.R2, approvalPolicy: 'never' });
  assert.equal(d.blocked, true);
  assert.match(d.blockedReason, /fail-closed/);

  // 而 R0/R1 不需要审批，在 never 策略下仍可执行
  const readOnly = decideApproval({ risk: Risk.R0, approvalPolicy: 'never' });
  assert.equal(readOnly.blocked, false);
  assert.equal(readOnly.requiresApproval, false);
});

test('maxRisk 只升不降', () => {
  assert.equal(maxRisk(Risk.R0, Risk.R3), Risk.R3);
  assert.equal(maxRisk(Risk.R2, Risk.R1), Risk.R2);
  assert.throws(() => maxRisk('RX', Risk.R1), /unknown risk/);
});

test('审批文案含目标与影响面（ApprovalRequest.reason 是唯一自由文本通道）', () => {
  const reason = buildApprovalReason({
    effectiveRisk: Risk.R3,
    target: { label: 'vm-prod', hostname: '10.0.0.9' },
    escalatedBy: [],
  });
  assert.match(reason, /vm-prod \(10\.0\.0\.9\)/);
  assert.match(reason, /不可逆/);
  assert.match(reason, /复述目标主机名/);
});

test('未知风险级直接抛错，不静默降级', () => {
  assert.throws(() => decideApproval({ risk: 'R9' }), /unknown risk/);
});

test('默认策略与用户决策一致：autoAllowUpTo = R1', () => {
  assert.equal(DEFAULT_POLICY.autoAllowUpTo, 'R1');
  assert.equal(DEFAULT_POLICY.alwaysAskFrom, 'R2');
});
