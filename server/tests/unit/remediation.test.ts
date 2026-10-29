import assert from 'node:assert/strict';
import { test } from 'node:test';
import { remediationPrompt, type Task } from '../../src/lib/tasks';

const base: Task = {
  key: 'k', hostId: 'h', host: 'web1', osId: 'amzn', root: '__os__', name: 'OS', exposure: 'public',
  kev: 2, critical: 3, packages: [{ name: 'openssl', ecosystem: 'rpm', current: '1:3.0.1', target: '1:3.0.8', kev: 1, critical: 1 }],
  reboot: true, command: 'sudo dnf upgrade --releasever=latest openssl', status: 'todo', owner: '', due: null, note: '', overdue: false, protects: [],
};

test('includes the command, packages and reboot note', () => {
  const p = remediationPrompt(base);
  assert.match(p, /sudo dnf upgrade --releasever=latest openssl/);
  assert.match(p, /openssl: 1:3\.0\.1 → 1:3\.0\.8/);
  assert.match(p, /reboot/);
  assert.doesNotMatch(p, /共用ホスティング/);
});

test('pull hosts get the control-panel note', () => {
  const p = remediationPrompt({ ...base, root: '/home/u/www', name: 'shop' }, { pull: true });
  assert.match(p, /共用ホスティング/);
  assert.match(p, /コントロールパネル/);
});
