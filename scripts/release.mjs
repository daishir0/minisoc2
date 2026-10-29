// Build, sign and publish the agent into the server's download directory:
//   <dist>/minisoc2-agent-<ver>.mjs   single-file build (what self-update downloads)
//   <dist>/minisoc2-agent.tgz         npm package of the latest build (for `npx <url>`)
//   <dist>/manifest.json             { latest, versions: { ver: { file, sha256, signature } } }
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { agentDistDir, loadEnv, repoRoot, signingKeyPath } from './env.mjs';

const env = loadEnv();
const keyFile = signingKeyPath(env);
if (!existsSync(keyFile)) {
  console.error(`signing key not found: ${keyFile} (run "npm run keygen")`);
  process.exit(1);
}
const agentDir = join(repoRoot, 'agent');
execFileSync(process.execPath, [join(agentDir, 'scripts/build.mjs')], {
  stdio: 'inherit',
  env: { ...process.env, MINISOC2_PUBKEY_FILE: `${keyFile}.pub` },
});

const version = JSON.parse(readFileSync(join(agentDir, 'package.json'), 'utf8')).version;
const body = readFileSync(join(agentDir, 'dist/minisoc2.mjs'));
const digest = createHash('sha256').update(body).digest('hex');
const signature = sign(null, Buffer.from(`${version}\n${digest}`), createPrivateKey(readFileSync(keyFile))).toString('base64');

const dist = agentDistDir(env);
mkdirSync(dist, { recursive: true });
const file = `minisoc2-agent-${version}.mjs`;
writeFileSync(join(dist, file), body);
writeFileSync(join(dist, 'minisoc2-agent.mjs'), body); // stable name for manual copies

const tgz = execFileSync('npm', ['pack', '--silent', '--pack-destination', dist], { cwd: agentDir, encoding: 'utf8' }).trim().split('\n').pop();
copyFileSync(join(dist, tgz), join(dist, 'minisoc2-agent.tgz'));
renameSync(join(dist, tgz), join(dist, `minisoc2-agent-${version}.tgz`));

const manifestFile = join(dist, 'manifest.json');
const manifest = existsSync(manifestFile) ? JSON.parse(readFileSync(manifestFile, 'utf8')) : { versions: {} };
manifest.versions[version] = { file, sha256: digest, signature };
const keep = Object.keys(manifest.versions).sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).slice(-5);
manifest.versions = Object.fromEntries(keep.map((v) => [v, manifest.versions[v]]));
manifest.latest = keep[keep.length - 1];
writeFileSync(manifestFile, JSON.stringify(manifest, null, 2) + '\n');
console.log(`released agent ${version} -> ${dist}`);
