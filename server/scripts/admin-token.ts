// Maintenance helper: create an enroll token from the command line (e.g. for automation).
//   npx tsx scripts/admin-token.ts [label] [hours] [uses]
import 'dotenv/config';
import { pool, q } from '../src/lib/db';
import { randomToken, sha256hex } from '../src/lib/secrets';

const [label = 'cli', hours = '24', uses = '1'] = process.argv.slice(2);
const token = `enr_${randomToken(24)}`;
q("INSERT INTO enroll_tokens(token_hash, label, max_uses, expires_at) VALUES ($1,$2,$3, now() + ($4 || ' hours')::interval)", [sha256hex(token), label, Number(uses), hours])
  .then(() => console.log(token))
  .finally(() => pool.end());
