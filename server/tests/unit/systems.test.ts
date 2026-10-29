import assert from 'node:assert/strict';
import { test } from 'node:test';
import { excludedBy, globToRegExp, systemOf } from '../../src/lib/systems';

test('globToRegExp', () => {
  assert.ok(globToRegExp('data/**').test('data/env/1/workspace/NodeGoat/package-lock.json'));
  assert.ok(globToRegExp('data').test('data/x/package-lock.json'));
  assert.ok(!globToRegExp('data/**').test('src/data/package-lock.json'));
  assert.ok(globToRegExp('research/**/corpus*/**').test('research/vsat/corpus_e2/grav/composer.lock'));
  assert.ok(!globToRegExp('research/*/corpus/**').test('research/a/b/corpus/x'));
});

test('excludedBy', () => {
  const rules = ['data/**', 'research/**'].map((p) => ({ pattern: p, re: globToRegExp(p) }));
  assert.equal(excludedBy('/srv/app/data/x/package-lock.json', '/srv/app', rules), 'data/**');
  assert.equal(excludedBy('/srv/app/package-lock.json', '/srv/app', rules), null);
  assert.equal(excludedBy('/srv/other/data/x', '/srv/app', rules), null);
});

test('systemOf: longest manual root wins', () => {
  assert.equal(systemOf('/srv/app/mcp/q/venv/lib/python3.12/site-packages/a-1.dist-info', ['/srv'], ['/srv/app', '/srv/app/mcp/q']), '/srv/app/mcp/q');
});

import { serviceOsPackage, serviceRuntime, serviceSystem } from '../../src/lib/systems';

test('service links', () => {
  const envs = ['/opt/conda', '/opt/conda/envs/311'];
  assert.equal(serviceSystem('/srv/apps/album', ['/srv/apps'], []), '/srv/apps/album');
  assert.equal(serviceSystem('/srv/apps', ['/srv/apps'], []), null);
  assert.equal(serviceSystem('/usr/bin', ['/srv/apps'], []), null);
  assert.equal(serviceSystem('/srv/apps/x/mcp/q', ['/srv/apps'], ['/srv/apps/x', '/srv/apps/x/mcp/q']), '/srv/apps/x/mcp/q');
  assert.equal(serviceRuntime('/opt/conda/envs/311/bin/uvicorn', undefined, envs, '/srv/apps/album'), '/opt/conda/envs/311');
  assert.equal(serviceRuntime('/usr/bin/bash', '311', envs, '/srv/apps/kururin'), '/opt/conda/envs/311');
  assert.equal(serviceRuntime('/srv/apps/m/.venv/bin/python', undefined, envs, '/srv/apps/m'), null);
  assert.equal(serviceOsPackage('nodejs24-npm'), 'nodejs24');
  assert.equal(serviceOsPackage('bash'), null);
});
