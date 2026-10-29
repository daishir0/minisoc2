import { Pool, type PoolClient, type QueryResultRow } from 'pg';

// One pool per process; survives Next.js dev hot reloads via globalThis.
const g = globalThis as unknown as { __minisoc2Pool?: Pool };
// Sessions use the server's time zone so "today" and daily groupings match what users see.
const TZ = process.env.MINISOC2_TZ || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
export const pool = g.__minisoc2Pool ?? new Pool({ connectionString: process.env.DATABASE_URL, max: 8, options: `-c timezone=${TZ}` });
g.__minisoc2Pool = pool;

export async function q<T extends QueryResultRow = QueryResultRow>(sql: string, params: unknown[] = []): Promise<T[]> {
  return (await pool.query<T>(sql, params)).rows;
}

export async function q1<T extends QueryResultRow = QueryResultRow>(sql: string, params: unknown[] = []): Promise<T | null> {
  return (await q<T>(sql, params))[0] ?? null;
}

export async function tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await fn(c);
    await c.query('COMMIT');
    return r;
  } catch (e) {
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }
}
