// Remove the fixtures created by the E2E suite (sessions of the test admin go with it via ON DELETE CASCADE).
import 'dotenv/config';
import { pool, q } from '../src/lib/db';

Promise.all([
  q("DELETE FROM watch_cves WHERE cve='CVE-2099-0001'"),
  q("DELETE FROM enroll_tokens WHERE label='e2e-test'"),
  q("DELETE FROM change_events WHERE kind='ops' AND title LIKE '%@example.invalid）'"),
]).finally(() => pool.end());
