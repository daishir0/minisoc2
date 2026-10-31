// Resident control channel: hold one outbound WebSocket to the server and act on pushed verbs
// (collect / update) in near real time. This is a convenience layer over the cron schedule, which
// stays in place as the reliable fallback — if the socket is down, hourly `run` and `*/5 checkin`
// still work. The agent only ever RUNS ITSELF (read-only collection); it never executes anything the
// socket hands it, so the set of verbs is fixed and there is no remote-exec surface.
import WebSocket from 'ws';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { loadConfig, saveConfig, minisoc2Home, type AgentConfig } from './config.js';

// Only these fields can be set by a server-pushed config. Credentials (server/hostId/hostToken) are
// never accepted, and nothing here lets the server run code — the agent stays read-only.
const CONFIG_FIELDS: (keyof AgentConfig)[] = ['scanPaths', 'skipDirs', 'aidePaths', 'aideExcludes', 'logFiles', 'journal', 'useSudo', 'aide', 'pin', 'autoUpdate', 'pythonEnvs'];

function applyConfig(payload: Record<string, unknown> | undefined): boolean {
  if (!payload) return false;
  const cfg = loadConfig();
  if (!cfg) return false;
  let changed = false;
  for (const k of CONFIG_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(payload, k)) { (cfg as unknown as Record<string, unknown>)[k] = payload[k]; changed = true; }
  }
  if (changed) saveConfig(cfg);
  return changed;
}

function wsUrl(server: string): string {
  const u = server.replace(/\/+$/, '');
  if (u.startsWith('https://')) return 'wss://' + u.slice(8) + '/api/v1/ws';
  if (u.startsWith('http://')) return 'ws://' + u.slice(7) + '/api/v1/ws';
  return u + '/api/v1/ws';
}

export async function waitLoop(cfg: AgentConfig, version: string): Promise<void> {
  const url = wsUrl(cfg.server);
  const self = join(minisoc2Home(), 'minisoc2.mjs');
  let stopped = false;
  let attempt = 0;
  let collecting = false;
  let ws: WebSocket | null = null;

  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    process.on(sig, () => { stopped = true; try { ws?.close(); } catch { /* */ } process.exit(0); });
  }

  // Run a full collect+report in a child process so a self-update (which re-execs) or a failing
  // report (which exits non-zero) never takes down this long-lived daemon.
  const collect = (why: string) => {
    if (collecting) { console.log(`[wait] ${why}: collect already running, skipped`); return; }
    collecting = true;
    console.log(`[wait] ${why}: running collect`);
    const child = spawn(process.execPath, [self, 'run'], { stdio: 'inherit' });
    child.on('exit', (code) => { collecting = false; console.log(`[wait] collect exited ${code}`); });
    child.on('error', (e) => { collecting = false; console.log(`[wait] collect error: ${e.message}`); });
  };

  const connectOnce = () => new Promise<void>((resolve) => {
    const sock = new WebSocket(url, { handshakeTimeout: 15_000 });
    ws = sock;
    let buffer = '';
    let alive: ReturnType<typeof setInterval> | null = null;
    let last = Date.now();

    const done = () => { if (alive) clearInterval(alive); resolve(); };

    sock.on('open', () => {
      attempt = 0;
      last = Date.now();
      sock.send(JSON.stringify({ v: 1, type: 'hello', payload: { token: cfg.hostToken, version } }) + '\n');
      // if the server stops pinging (dead peer / NAT drop), reconnect
      alive = setInterval(() => { if (Date.now() - last > 90_000) { try { sock.terminate(); } catch { /* */ } } }, 30_000);
    });
    sock.on('ping', () => { last = Date.now(); });
    sock.on('pong', () => { last = Date.now(); });
    sock.on('message', (data: WebSocket.RawData) => {
      last = Date.now();
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        let env: { type?: string; payload?: Record<string, unknown> };
        try { env = JSON.parse(line); } catch { continue; }
        if (env.type === 'welcome') console.log('[wait] connected');
        else if (env.type === 'denied') { console.error('[wait] auth denied by server'); try { sock.close(); } catch { /* */ } }
        else if (env.type === 'collect' || env.type === 'update') collect(env.type);
        else if (env.type === 'config') {
          if (applyConfig(env.payload)) { console.log('[wait] config updated from server'); collect('config-applied'); }
          else console.log('[wait] config push ignored (no applicable fields)');
        }
        else if (env.type === 'rematch') { /* server-side only; nothing to do on the host */ }
      }
    });
    sock.on('close', done);
    sock.on('error', () => { /* close will follow */ });
  });

  console.log(`[wait] control channel to ${url}`);
  while (!stopped) {
    await connectOnce();
    if (stopped) break;
    attempt++;
    const backoff = Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5)) + Math.floor(Math.random() * 1000);
    await new Promise((r) => setTimeout(r, backoff));
  }
}
