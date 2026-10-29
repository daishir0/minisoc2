// Test helper: create or delete a temporary admin for E2E runs.
//   npx tsx scripts/e2e-admin.ts create <email> <password> | delete <email>
import 'dotenv/config';
import { createAdmin } from '../src/lib/auth';
import { pool, q } from '../src/lib/db';

const [op, email, password] = process.argv.slice(2);
(op === 'create' ? createAdmin(email, password).then(() => undefined) : q('DELETE FROM admin_users WHERE email=$1', [email.toLowerCase()]).then(() => undefined))
  .then(() => console.log(`${op} ${email}`))
  .finally(() => pool.end());
