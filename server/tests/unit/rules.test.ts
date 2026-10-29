import assert from 'node:assert/strict';
import { test } from 'node:test';
import { matchLine } from '../../src/lib/rules';

const hit = (source: string, line: string) => matchLine(source, line, new Date()).map((h) => `${h.rule.id}(${h.grp})`);

test('ssh', () => {
  assert.deepEqual(hit('journal:sshd.service', 'sshd: Accepted publickey for u from 203.0.113.5 port 5555 ssh2'), ['ssh_accept_new_ip(203.0.113.5)']);
  assert.deepEqual(hit('journal:sshd.service', 'sshd: Failed password for invalid user admin from 198.51.100.7 port 2222 ssh2'), ['ssh_bruteforce(198.51.100.7)']);
  assert.deepEqual(hit('unified:sshd', 'sshd: Accepted keyboard-interactive/pam for u from 2001:db8::1 port 50000 ssh2'), ['ssh_accept_new_ip(2001:db8::1)']);
});

test('sudo and accounts', () => {
  assert.deepEqual(hit('journal:x', 'sudo: bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls'), ['sudo_new_user(bob)']);
  assert.deepEqual(hit('journal:sudo', 'sudo: pam_unix(sudo:auth): authentication failure; logname=bob'), ['sudo_auth_failure()']);
  assert.deepEqual(hit('journal:x', 'useradd[123]: new user: name=eve, UID=1002'), ['account_created(eve)']);
});

test('web', () => {
  const f = 'file:/var/log/httpd/site-access.log';
  assert.deepEqual(hit(f, '198.51.100.9 - - [26/Oct/2026:10:00:00 +0900] "GET /.env HTTP/1.1" 200 512 "-" "curl"'), ['web_sensitive_200(198.51.100.9)']);
  assert.deepEqual(hit(f, '198.51.100.9 - - [26/Oct/2026:10:00:00 +0900] "GET /.env HTTP/1.1" 403 199 "-" "curl"'), []);
  assert.deepEqual(hit(f, '198.51.100.9 - - [26/Oct/2026:10:00:00 +0900] "GET /p?f=.env HTTP/1.1" 200 512 "-" "-"'), []);
  assert.deepEqual(hit(f, '198.51.100.9 - - [26/Oct/2026:10:00:00 +0900] "GET /x HTTP/1.1" 404 10 "-" "-"'), ['web_scan_burst(198.51.100.9)']);
  assert.deepEqual(hit('journal:x', '"GET /.env HTTP/1.1" 200 512'), []); // web rules only apply to access logs
});

test('windows events', () => {
  assert.deepEqual(hit('eventlog:Security', 'EventID=4625 TargetUserName=admin LogonType=3 IpAddress=192.0.2.44'), ['win_logon_failure_burst(192.0.2.44)']);
  assert.deepEqual(hit('eventlog:Security', 'EventID=4624 TargetUserName=bob LogonType=10 IpAddress=192.0.2.45'), ['win_rdp_new_ip(192.0.2.45)']);
  assert.deepEqual(hit('eventlog:Security', 'EventID=4624 TargetUserName=bob LogonType=3 IpAddress=192.0.2.45'), []);
  assert.deepEqual(hit('eventlog:Security', 'EventID=1102 SubjectUserName=bob'), ['win_log_cleared()']);
  assert.deepEqual(hit('eventlog:System', 'EventID=7045 ServiceName=Evil Svc ImagePath=C:\\x.exe'), ['win_service_installed(Evil Svc)']);
});
