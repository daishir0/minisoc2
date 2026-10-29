import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pool, q, tx } from '../src/lib/db';

export { pool };

// Apply migrations/*.sql in name order, each once.
export async function migrate(dir = join(process.cwd(), 'migrations')): Promise<string[]> {
  await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
  const done = new Set((await q<{ name: string }>('SELECT name FROM schema_migrations')).map((r) => r.name));
  const applied: string[] = [];
  for (const f of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) {
    if (done.has(f)) continue;
    await tx(async (c) => {
      await c.query(readFileSync(join(dir, f), 'utf8'));
      await c.query('INSERT INTO schema_migrations(name) VALUES ($1)', [f]);
    });
    applied.push(f);
  }
  return applied;
}
