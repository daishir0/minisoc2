import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compileRule, matchSigma } from '../../src/lib/sigma';

test('compiles a keyword rule (AND of selection, OR within a field)', () => {
  const c = compileRule({
    id: 'r1', title: 'Suspicious chattr', level: 'high', logsource: { product: 'linux' },
    detection: { sel: { 'a|contains': ['chattr', 'lsattr'] }, condition: 'sel' },
  } as never);
  assert.ok(c);
  assert.equal(c!.level, 'high');
  assert.deepEqual(c!.needles, [['chattr', 'lsattr']]);
});

test('multiple fields become AND groups', () => {
  const c = compileRule({
    id: 'r2', title: 'two fields', level: 'medium', logsource: { product: 'linux' },
    detection: { sel: { 'cmd|contains': 'wget', 'arg|contains': 'http' }, condition: 'sel' },
  } as never);
  assert.ok(c);
  assert.equal(c!.needles.length, 2);
});

test('rejects conditions with or/not and non-linux products', () => {
  assert.equal(compileRule({ id: 'r3', logsource: { product: 'linux' }, detection: { a: { 'x|contains': 'abcd' }, b: { 'y|contains': 'efgh' }, condition: 'a or b' } } as never), null);
  assert.equal(compileRule({ id: 'r4', logsource: { product: 'linux' }, detection: { a: { 'x|contains': 'abcd' }, condition: 'a and not b' } } as never), null);
  assert.equal(compileRule({ id: 'r5', logsource: { product: 'windows' }, detection: { a: ['abcd'], condition: 'a' } } as never), null);
});

test('drops too-short needles and skips the rule if a group empties', () => {
  assert.equal(compileRule({ id: 'r6', logsource: { product: 'linux' }, detection: { a: { 'x|contains': ['ab', 'cd'] }, condition: 'a' } } as never), null);
});

test('matchSigma fires only when every group matches', () => {
  const c = compileRule({ id: 'r7', title: 't', level: 'high', logsource: { product: 'linux' }, detection: { sel: { 'cmd|contains': 'wget', 'arg|contains': 'http' }, condition: 'sel' } } as never)!;
  const rules = [{ rule: { id: c.id, title: c.title, severity: c.level, pattern: /(?:)/, alert: true } as never, sourceRe: null, needles: c.needles }];
  assert.equal(matchSigma(rules, 'journal:x', 'running wget http://evil', new Date()).length, 1);
  assert.equal(matchSigma(rules, 'journal:x', 'running wget only', new Date()).length, 0);
});
