import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseComposer, parsePorts, parseRequirements, safePath } from '../../src/lib/pullssh';

test('safePath blocks traversal and shell metacharacters', () => {
  assert.equal(safePath('~/www'), true);
  assert.equal(safePath('/home/user/log/*.access_log'), true);
  assert.equal(safePath('../etc'), false);
  assert.equal(safePath('a; rm -rf /'), false);
  assert.equal(safePath('a$(whoami)'), false);
  assert.equal(safePath('a`id`'), false);
});

test('parseComposer maps packages to Packagist', () => {
  const lock = JSON.stringify({ packages: [{ name: 'monolog/monolog', version: 'v2.9.1' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: '10.0.0' }] });
  const r = parseComposer(lock, '/w/composer.lock');
  assert.deepEqual(r, [
    { ecosystem: 'Packagist', name: 'monolog/monolog', version: '2.9.1', source: '/w/composer.lock' },
    { ecosystem: 'Packagist', name: 'phpunit/phpunit', version: '10.0.0', source: '/w/composer.lock' },
  ]);
  assert.deepEqual(parseComposer('not json', '/w/composer.lock'), []);
});

test('parseRequirements takes only == pins', () => {
  const r = parseRequirements('Django==4.2.1\nrequests>=2\n# c\nflask == 3.0.0', '/w/requirements.txt');
  assert.deepEqual(r.map((p) => `${p.name}@${p.version}`), ['Django@4.2.1', 'flask@3.0.0']);
});

test('parsePorts reads ss/netstat listen lines', () => {
  const ss = 'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\nLISTEN 0 128 [::]:443 [::]:*';
  const ports = parsePorts(ss);
  assert.ok(ports.some((p) => p.port === 8080 && p.addr === '0.0.0.0'));
  assert.ok(ports.some((p) => p.port === 443 && p.proto === 'tcp6'));
});
