/**
 * 参数校验与"未接线即阻断"的单测 —— 对应推演发现 F2 / F5。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { findUnwiredParams, normalizeParams, validateParams } from '../src/params.js';

const ACTION = {
  id: 'demo.action',
  params: {
    type: 'object',
    properties: {
      flag: { type: 'boolean', default: false },
      mode: { type: 'string', enum: ['a', 'b'], default: 'a' },
      count: { type: 'integer' },
      list: { type: 'array', items: { type: 'string' }, default: [] },
    },
    additionalProperties: false,
  },
  wiredParams: ['count'],
};

test('类型不符被拒', () => {
  assert.deepEqual(validateParams(ACTION, { flag: 'yes' }), ['参数 "flag" 应为布尔值']);
  assert.deepEqual(validateParams(ACTION, { count: 1.5 }), ['参数 "count" 应为整数']);
  assert.deepEqual(validateParams(ACTION, { list: 'x' }), ['参数 "list" 应为数组']);
});

test('未知参数被拒，并列出可接受的名字', () => {
  const errs = validateParams(ACTION, { nope: 1 });
  assert.equal(errs.length, 1);
  assert.match(errs[0], /未知参数 "nope"/);
  assert.match(errs[0], /flag, mode, count, list/);
});

test('enum 受限被拒', () => {
  assert.deepEqual(validateParams(ACTION, { mode: 'c' }), ['参数 "mode" 必须是 a / b 之一']);
});

test('params 不是对象被拒', () => {
  assert.deepEqual(validateParams(ACTION, null), ['params 必须是对象']);
  assert.deepEqual(validateParams(ACTION, []), ['params 必须是对象']);
});

test('合法参数通过', () => {
  assert.deepEqual(validateParams(ACTION, { flag: true, mode: 'b', count: 3, list: ['x'] }), []);
  assert.deepEqual(validateParams(ACTION, {}), [], '全部可选时传空对象应通过');
});

test('必填参数缺失被拒 —— 支持两种声明写法', () => {
  // 写法一：JSON Schema 标准的对象级 required 数组
  const jsonSchemaStyle = {
    id: 'r1',
    params: {
      type: 'object',
      properties: { must: { type: 'string' } },
      required: ['must'],
      additionalProperties: false,
    },
  };
  assert.deepEqual(validateParams(jsonSchemaStyle, {}), ['缺少必填参数 "must"']);
  assert.deepEqual(validateParams(jsonSchemaStyle, { must: 'ok' }), []);

  // 写法二：DSH 的 ParameterSchemaSpec 风格，逐属性 required: true
  const dshSpecStyle = {
    id: 'r2',
    params: {
      type: 'object',
      properties: { must: { type: 'string', required: true } },
      additionalProperties: false,
    },
  };
  assert.deepEqual(validateParams(dshSpecStyle, {}), ['缺少必填参数 "must"']);
  assert.deepEqual(validateParams(dshSpecStyle, { must: 'ok' }), []);

  // 有默认值的属性即使被标为必填，也不该要求调用方显式传
  const withDefault = {
    id: 'r3',
    params: {
      type: 'object',
      properties: { mode: { type: 'string', default: 'a', required: true } },
      additionalProperties: false,
    },
  };
  assert.deepEqual(validateParams(withDefault, {}), []);
});

test('归一化：与默认值相同的显式传参被丢弃', () => {
  assert.deepEqual(normalizeParams(ACTION, { flag: false, mode: 'a', list: [] }), {});
  assert.deepEqual(normalizeParams(ACTION, { flag: true, mode: 'a' }), { flag: true });
  assert.deepEqual(normalizeParams(ACTION, { count: 0 }), { count: 0 }, '0 不等于默认（默认未声明）');
});

test('未接线参数：仅列真正偏离默认值的', () => {
  // flag/mode/list 的默认值形态 → 等价于没传 → 不算"未接线"
  assert.deepEqual(findUnwiredParams(ACTION, { flag: false, mode: 'a', list: [] }), []);
  // count 已接线 → 不算
  assert.deepEqual(findUnwiredParams(ACTION, { count: 5 }), []);
  // flag 偏离默认且未接线 → 报出
  assert.deepEqual(findUnwiredParams(ACTION, { flag: true }), ['flag']);
  assert.deepEqual(findUnwiredParams(ACTION, { flag: true, count: 5 }), ['flag']);
});

test('未声明 wiredParams 时，任何偏离默认的参数都算未接线（fail-closed 默认）', () => {
  const noWired = { ...ACTION, wiredParams: undefined };
  assert.deepEqual(findUnwiredParams(noWired, { count: 5 }), ['count']);
});
