// Create the ed25519 key pair that signs agent builds. The private key never leaves this server.
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { loadEnv, signingKeyPath } from './env.mjs';

const key = signingKeyPath(loadEnv());
if (existsSync(key) && !process.argv.includes('--force')) {
  console.error(`${key} already exists (use --force to replace it; existing agents will then reject new builds)`);
  process.exit(1);
}
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
mkdirSync(dirname(key), { recursive: true, mode: 0o700 });
writeFileSync(key, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
writeFileSync(`${key}.pub`, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
console.log(`private: ${key}\npublic:  ${key}.pub`);
