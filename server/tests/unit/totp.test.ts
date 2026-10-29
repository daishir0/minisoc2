import assert from 'node:assert/strict';
import { test } from 'node:test';
import { base32Decode, base32Encode, codeAt, generateSecret, otpauthURL, verifyTotp } from '../../src/lib/totp';

// RFC 6238 test secret "12345678901234567890" (ASCII) in base32.
const RFC = base32Encode(Buffer.from('12345678901234567890'));

test('base32 roundtrip', () => {
  const b = Buffer.from('hello world!');
  assert.deepEqual(base32Decode(base32Encode(b)), b);
  assert.equal(RFC, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
});

test('RFC 6238 vectors (6-digit truncation of the SHA-1 cases)', () => {
  // T=59 -> counter 1 -> 94287082; T=1111111109 -> counter 37037036 -> 07081804
  assert.equal(codeAt(RFC, 1), '287082');
  assert.equal(codeAt(RFC, 37037036), '081804');
});

test('verifyTotp accepts the code for the given time and tolerates drift', () => {
  const now = 59_000; // T=59s
  assert.equal(verifyTotp(RFC, '287082', 1, now), true);
  assert.equal(verifyTotp(RFC, '287082', 1, now + 30_000), true); // one step late, within window
  assert.equal(verifyTotp(RFC, '287082', 1, now + 90_000), false); // too far
  assert.equal(verifyTotp(RFC, '000000', 1, now), false);
  assert.equal(verifyTotp(RFC, 'abc', 1, now), false);
  assert.equal(verifyTotp('', '287082', 1, now), false);
});

test('generateSecret is valid base32 of expected length', () => {
  const s = generateSecret();
  assert.match(s, /^[A-Z2-7]+$/);
  assert.equal(base32Decode(s).length, 20);
});

test('otpauthURL format', () => {
  const url = otpauthURL('admin@example.com', RFC);
  assert.match(url, /^otpauth:\/\/totp\/minisoc2:admin%40example\.com\?/);
  assert.match(url, /secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ/);
  assert.match(url, /issuer=minisoc2/);
});
