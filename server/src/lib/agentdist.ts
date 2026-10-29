import { join } from 'node:path';

// Directory filled by `npm run agent:release` at the repository root.
export function agentDistDir(): string {
  const p = process.env.AGENT_DIST_DIR || 'data/agent';
  return p.startsWith('/') ? p : join(process.cwd(), p);
}
