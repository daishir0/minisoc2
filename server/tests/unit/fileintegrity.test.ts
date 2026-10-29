import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pathSeverity } from '../../src/lib/fileintegrity';

test('security-sensitive paths are critical', () => {
  for (const p of ['/root/.ssh/authorized_keys', '/home/alice/.ssh/authorized_keys', '/etc/sudoers',
    '/etc/sudoers.d/90-cloud', '/etc/passwd', '/etc/shadow', '/etc/ssh/sshd_config']) {
    assert.equal(pathSeverity(p), 'critical', p);
  }
});

test('executables, cron, systemd units, boot are high', () => {
  for (const p of ['/usr/bin/sshd', '/usr/sbin/sudo', '/bin/ls', '/usr/local/bin/app',
    '/etc/cron.d/job', '/etc/crontab', '/etc/systemd/system/x.service', '/boot/grub2/grub.cfg']) {
    assert.equal(pathSeverity(p), 'high', p);
  }
});

test('other /etc is medium, everything else low', () => {
  assert.equal(pathSeverity('/etc/hosts'), 'medium');
  assert.equal(pathSeverity('/etc/resolv.conf'), 'medium');
  assert.equal(pathSeverity('/opt/app/data.txt'), 'low');
  assert.equal(pathSeverity('/var/www/index.html'), 'low');
});
