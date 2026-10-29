import { gunzipSync } from 'node:zlib';

const MAX_COMPRESSED = 50 * 1024 * 1024;
const MAX_JSON = 300 * 1024 * 1024;

export class BodyError extends Error {
  constructor(message: string, public status = 400) {
    super(message);
  }
}

// Agents send gzip-compressed JSON (inventories can be several MB).
export async function readJson<T>(req: Request): Promise<T> {
  const raw = Buffer.from(await req.arrayBuffer());
  if (raw.length > MAX_COMPRESSED) throw new BodyError('payload too large', 413);
  let buf = raw;
  if ((req.headers.get('content-encoding') ?? '').includes('gzip')) {
    try {
      buf = gunzipSync(raw, { maxOutputLength: MAX_JSON });
    } catch {
      throw new BodyError('invalid gzip body');
    }
  }
  try {
    return JSON.parse(buf.toString('utf8')) as T;
  } catch {
    throw new BodyError('invalid JSON body');
  }
}

// Tiny fixed-window limiter (per process) for unauthenticated endpoints.
const hits = new Map<string, { n: number; reset: number }>();
export function rateLimited(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const h = hits.get(key);
  if (!h || h.reset < now) {
    hits.set(key, { n: 1, reset: now + windowMs });
    return false;
  }
  h.n++;
  return h.n > max;
}

// Check without counting (count failures separately with rateLimited).
export function isLimited(key: string, max: number): boolean {
  const h = hits.get(key);
  return !!h && h.reset >= Date.now() && h.n >= max;
}

export function clientIp(req: Request): string {
  return (req.headers.get('x-forwarded-for') ?? '').split(',')[0].trim() || 'unknown';
}
