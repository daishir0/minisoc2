import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareVersions, inRange, normalizeCve } from '../../src/lib/cvelookup';

test('compareVersions', () => {
  assert.ok(compareVersions('1.2.10', '1.2.9') > 0);
  assert.ok(compareVersions('1.2.6', '1.2.6') === 0);
  assert.ok(compareVersions('16.3.3', '16.4.1') < 0);
  assert.ok(compareVersions('1.0.0-rc.1', '1.0.0') < 0);
  assert.ok(compareVersions('v2.0.0', '1.9.9') > 0);
  assert.ok(compareVersions('1.0rc1', '1.0') < 0);
});

test('inRange (GHSA ranges)', () => {
  assert.equal(inRange('1.2.5', '>= 1.0.0, < 1.2.6'), true);
  assert.equal(inRange('1.2.6', '>= 1.0.0, < 1.2.6'), false);
  assert.equal(inRange('0.0.8', '< 0.2.4'), true);
  assert.equal(inRange('2.0.0', '= 2.0.0'), true);
  assert.equal(inRange('16.3.3', '>= 16.0.0, < 16.4.1'), true);
  assert.equal(inRange('1.0', 'garbage'), null);
});

test('normalizeCve', () => {
  assert.equal(normalizeCve(' cve-2026-109618 '), 'CVE-2026-109618');
  assert.equal(normalizeCve('CVE-26-1'), null);
});
