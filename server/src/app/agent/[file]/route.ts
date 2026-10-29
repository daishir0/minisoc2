import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { agentDistDir } from '@/lib/agentdist';

const TYPES: Record<string, string> = { json: 'application/json', mjs: 'text/javascript', tgz: 'application/gzip' };

// Public downloads: the signed manifest, single-file builds and the npm tarball for `npx <url>`.
export async function GET(_req: Request, ctx: { params: Promise<{ file: string }> }) {
  const { file } = await ctx.params;
  if (!/^(manifest\.json|minisoc2-agent(-\d+\.\d+\.\d+)?\.(mjs|tgz))$/.test(file)) return new Response('not found', { status: 404 });
  try {
    const body = await readFile(join(agentDistDir(), file));
    return new Response(body, {
      headers: { 'content-type': TYPES[file.split('.').pop()!], 'cache-control': !/-\d/.test(file) ? 'no-cache' : 'public, max-age=31536000, immutable' },
    });
  } catch {
    return new Response('not found', { status: 404 });
  }
}
