/**
 * `probeSatisfies` 的语义测试（M2-①）。
 *
 * 这是"校验"里唯一的判定逻辑，而且是个纯函数 —— 所以它必须被单测锁死。
 * 三条最要紧的语义：
 *   · 只比对 expect 里**列出**的字段；
 *   · expect 里列了、探测结果里没有 ⇒ **不满足**（绝不把"探测不到"当"符合预期"）；
 *   · 没有 expect ⇒ `null`（未判定），而不是 `true`。
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { probeSatisfies } from '../src/ssh.js';

test('全部字段相符 → true', () => {
  assert.equal(probeSatisfies({ count: 0, distro: 'debian' }, { count: 0 }), true);
});

test('只比对 expect 里列出的字段，其它字段不参与判定', () => {
  // distro 变了不影响 count 的判定
  assert.equal(probeSatisfies({ count: 0, distro: 'ubuntu' }, { count: 0 }), true);
});

test('值不符 → false', () => {
  assert.equal(probeSatisfies({ count: 12 }, { count: 0 }), false);
});

test('★ expect 里列了、但探测结果里没有该字段 → false（不把"探测不到"当符合预期）', () => {
  assert.equal(probeSatisfies({ foo: 1 }, { count: 0 }), false);
  assert.equal(probeSatisfies({}, { serviceKeyInstalled: true }), false);
  assert.equal(probeSatisfies(null, { count: 0 }), false);
});

test('布尔严格比对：null 不等于 false', () => {
  // 这是本项目的核心纪律之一：null 表示"没探测到"，不是"否"
  assert.equal(probeSatisfies({ serviceKeyInstalled: null }, { serviceKeyInstalled: false }), false);
  assert.equal(probeSatisfies({ serviceKeyInstalled: false }, { serviceKeyInstalled: false }), true);
  assert.equal(probeSatisfies({ serviceKeyInstalled: true }, { serviceKeyInstalled: true }), true);
});

test('没有 expect / 空 expect → null（未判定，不是通过）', () => {
  assert.equal(probeSatisfies({ count: 0 }, null), null);
  assert.equal(probeSatisfies({ count: 0 }, undefined), null);
  assert.equal(probeSatisfies({ count: 0 }, {}), null);
  // 非对象也是"无法判定"，而不是抛错 —— 判定函数不该成为新的失败点
  assert.equal(probeSatisfies({ count: 0 }, 'x'), null);
  assert.equal(probeSatisfies({ count: 0 }, [1, 2]), null);
});

test('数组按元素严格比对（顺序敏感）', () => {
  assert.equal(probeSatisfies({ idLike: ['debian', 'ubuntu'] }, { idLike: ['debian', 'ubuntu'] }), true);
  assert.equal(probeSatisfies({ idLike: ['ubuntu', 'debian'] }, { idLike: ['debian', 'ubuntu'] }), false);
  assert.equal(probeSatisfies({ idLike: ['debian'] }, { idLike: ['debian', 'ubuntu'] }), false);
  assert.equal(probeSatisfies({ idLike: 'debian' }, { idLike: ['debian'] }), false);
});

test('多字段：全中才为 true', () => {
  const state = { count: 0, serviceKeyInstalled: true };
  assert.equal(probeSatisfies(state, { count: 0, serviceKeyInstalled: true }), true);
  assert.equal(probeSatisfies(state, { count: 0, serviceKeyInstalled: false }), false);
});

test('数字 0 与字符串 "0" 不相等（不做类型宽松）', () => {
  assert.equal(probeSatisfies({ count: '0' }, { count: 0 }), false);
});
