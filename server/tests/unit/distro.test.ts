import assert from 'node:assert/strict';
import { test } from 'node:test';
import { trackerCandidates, ubuntuVerdict, classifyComponent, type UbuntuCve } from '../../src/lib/distro';

test('trackerCandidates derives series + flavor', () => {
  assert.deepEqual(trackerCandidates('linux-aws', '6.8.0-1066.69~22.04.1').names, ['linux-aws-6.8', 'linux-aws', 'linux-hwe-6.8', 'linux']);
  assert.deepEqual(trackerCandidates('linux-image-6.8.0-1066-aws', '6.8.0-1066.69').names[0], 'linux-aws-6.8');
  assert.deepEqual(trackerCandidates('openssl', '3.0.2').names, ['openssl']);
});

test('ubuntuVerdict: pending = vulnerable, correct series', () => {
  const uc: UbuntuCve = { priority: 'high', pkgs: [
    { name: 'linux-aws-6.8', release: 'jammy', status: 'pending', fixed: '6.8.0-1069.74~22.04.1' },
    { name: 'linux-aws', release: 'jammy', status: 'pending', fixed: '5.15.0-1120.127' },
  ]};
  const v = ubuntuVerdict('jammy', [{ name: 'linux-aws', version: '6.8.0-1066.69~22.04.1' }], uc);
  assert.equal(v.matched, true);
  assert.equal(v.red.length, 1);
  assert.match(v.red[0], /linux-aws-6\.8.*修正保留中/);
});

test('ubuntuVerdict: released older = vulnerable, newer = fixed', () => {
  const uc: UbuntuCve = { priority: 'high', pkgs: [{ name: 'openssl', release: 'jammy', status: 'released', fixed: '3.0.2-0ubuntu1.15' }] };
  assert.equal(ubuntuVerdict('jammy', [{ name: 'openssl', version: '3.0.2-0ubuntu1.10' }], uc).red.length, 1);
  assert.equal(ubuntuVerdict('jammy', [{ name: 'openssl', version: '3.0.2-0ubuntu1.18' }], uc).green.length, 1);
});

test('ubuntuVerdict: not-affected/DNE are skipped', () => {
  const uc: UbuntuCve = { priority: 'low', pkgs: [{ name: 'curl', release: 'jammy', status: 'not-affected', fixed: '' }] };
  const v = ubuntuVerdict('jammy', [{ name: 'curl', version: '7.81.0' }], uc);
  assert.equal(v.red.length + v.green.length, 0);
});

test('classifyComponent detects kernel', () => {
  assert.equal(classifyComponent('In the Linux kernel, the following vulnerability...'), 'kernel');
  assert.equal(classifyComponent('A flaw in nginx'), null);
});
