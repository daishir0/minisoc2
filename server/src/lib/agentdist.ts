import { join } from 'node:path';

// Directory filled by `npm run agent:release` at the repository root. The path is resolved at runtime
// from an env var; turbopackIgnore stops the bundler from tracing the whole project because of it
// (the dynamic join would otherwise be flagged and fail the production build).
export function agentDistDir(): string {
  const p = process.env.AGENT_DIST_DIR || 'data/agent';
  return p.startsWith('/') ? p : join(/*turbopackIgnore: true*/ process.cwd(), p);
}
