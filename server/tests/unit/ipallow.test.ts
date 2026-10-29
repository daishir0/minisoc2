import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ipAllowed, parseAllowList } from '../../src/lib/ipallow';

test('empty list allows everything', () => {
  assert.equal(ipAllowed('203.0.113.9', []), true);
  assert.equal(ipAllowed('203.0.113.9', null), true);
  assert.equal(ipAllowed('unknown', []), true);
});

test('exact IPv4', () => {
  assert.equal(ipAllowed('203.0.113.9', ['203.0.113.9']), true);
  assert.equal(ipAllowed('203.0.113.10', ['203.0.113.9']), false);
});

test('IPv4 CIDR', () => {
  assert.equal(ipAllowed('203.0.113.9', ['203.0.113.0/24']), true);
  assert.equal(ipAllowed('203.0.114.9', ['203.0.113.0/24']), false);
  assert.equal(ipAllowed('10.1.2.3', ['10.0.0.0/8']), true);
  assert.equal(ipAllowed('11.1.2.3', ['10.0.0.0/8']), false);
  assert.equal(ipAllowed('192.168.1.1', ['0.0.0.0/0']), true); // /0 matches all v4
});

test('restriction set but source unknown is denied', () => {
  assert.equal(ipAllowed('unknown', ['203.0.113.0/24']), false);
  assert.equal(ipAllowed('', ['203.0.113.0/24']), false);
});

test('IPv6 exact and CIDR', () => {
  assert.equal(ipAllowed('2001:db8::1', ['2001:db8::/32']), true);
  assert.equal(ipAllowed('2001:db9::1', ['2001:db8::/32']), false);
  assert.equal(ipAllowed('2001:db8::1', ['2001:db8::1']), true);
  assert.equal(ipAllowed('2001:db8:0:0:0:0:0:1', ['2001:db8::1']), true); // expanded form
});

test('v4 and v6 do not cross-match', () => {
  assert.equal(ipAllowed('203.0.113.9', ['2001:db8::/32']), false);
  assert.equal(ipAllowed('2001:db8::1', ['203.0.113.0/24']), false);
});

test('multiple entries: any match allows', () => {
  assert.equal(ipAllowed('10.0.0.5', ['203.0.113.0/24', '10.0.0.0/8']), true);
});

test('parseAllowList validates and splits', () => {
  const r = parseAllowList('203.0.113.0/24, 10.0.0.1\n2001:db8::/32\nnope\n999.1.1.1\n10.0.0.0/40');
  assert.deepEqual(r.ok, ['203.0.113.0/24', '10.0.0.1', '2001:db8::/32']);
  assert.deepEqual(r.bad, ['nope', '999.1.1.1', '10.0.0.0/40']);
});
