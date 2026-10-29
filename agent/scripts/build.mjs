// Bundle the agent into one dependency-free file: agent/dist/minisoc2.mjs
// The ed25519 public key that verifies self-updates is embedded at build time
// (MINISOC2_PUBKEY_FILE, default: the key next to SIGNING_KEY_PATH).
import { build } from 'esbuild';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const pubFile = process.env.MINISOC2_PUBKEY_FILE;
if (!pubFile || !existsSync(pubFile)) {
  console.error('MINISOC2_PUBKEY_FILE must point to the ed25519 public key (run "npm run keygen" first)');
  process.exit(1);
}
const pubkey = readFileSync(pubFile, 'utf8');

await build({
  entryPoints: [join(root, 'src/main.ts')],
  outfile: join(root, 'dist/minisoc2.mjs'),
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  banner: { js: '#!/usr/bin/env node' },
  define: { __VERSION__: JSON.stringify(pkg.version), __PUBKEY__: JSON.stringify(pubkey) },
  legalComments: 'none',
});
console.log(`built agent ${pkg.version} -> agent/dist/minisoc2.mjs`);
