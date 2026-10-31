// Real-time control channel (server -> agent). Agents dial out and hold one outbound WebSocket
// (NAT-friendly, like the afk runner). The server pushes a small, FIXED set of verbs — collect /
// rematch / update — and nothing else: the agent stays READ-ONLY, so even a compromised server
// cannot run arbitrary commands on a host. Delivery is best-effort; the hourly cron + the
// collect_requested flag remain the reliable fallback when the socket is down.
import { WebSocketServer, WebSocket } from 'ws';
import { Client } from 'pg';
import { q } from '../src/lib/db';
import { safeEqual, sha256hex } from '../src/lib/secrets';

type Verb = 'collect' | 'rematch' | 'update';
const VERBS = new Set<Verb>(['collect', 'rematch', 'update']);
const PORT = Number(process.env.AGENT_WS_PORT ?? 3043);
const log = (...a: unknown[]) => console.log(new Date().toISOString(), '[ws]', ...a);

// one live socket per host (a reconnect replaces the old one)
const conns = new Map<string, WebSocket>();

function sendEnv(ws: WebSocket, type: string, payload: Record<string, unknown> = {}): void {
  if (ws.readyState !== WebSocket.OPEN) return;
  try { ws.send(JSON.stringify({ v: 1, type, payload }) + '\n'); } catch { /* ignore */ }
}

// Deliver a verb to a host if it is connected right now. Returns false if no live socket.
export function pushToHost(hostId: string, verb: Verb): boolean {
  const ws = conns.get(hostId);
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  sendEnv(ws, verb);
  return true;
}

export function isOnline(hostId: string): boolean {
  const ws = conns.get(hostId);
  return !!ws && ws.readyState === WebSocket.OPEN;
}

async function authenticate(token: string): Promise<string | null> {
  const id = token.split('.')[0];
  if (!/^[0-9a-f-]{36}$/.test(id)) return null;
  const rows = await q<{ token_hash: string; disabled: boolean }>('SELECT token_hash, disabled FROM hosts WHERE id=$1', [id]);
  const h = rows[0];
  if (!h || h.disabled || !safeEqual(h.token_hash, sha256hex(token))) return null;
  return id;
}

async function markSeen(hostId: string): Promise<void> {
  // ws_seen_at marks "connected right now" (stamped on connect + every pong); last_checkin_at is kept
  // in sync too so the existing check-in display stays fresh while the channel is up.
  try { await q('UPDATE hosts SET ws_seen_at=now(), last_checkin_at=now() WHERE id=$1', [hostId]); } catch { /* best effort */ }
}

// Postgres LISTEN/NOTIFY bridges the console (which runs in the Next process) to this worker: a
// requestCollect there does NOTIFY agent_cmd, '<hostId>:collect' and we push it to the live socket.
async function startListener(): Promise<void> {
  const connect = async () => {
    const c = new Client({ connectionString: process.env.DATABASE_URL });
    c.on('notification', (msg) => {
      const [hostId, verb] = String(msg.payload ?? '').split(':');
      if (!hostId || !VERBS.has(verb as Verb)) return;
      const ok = pushToHost(hostId, verb as Verb);
      log(`notify ${verb} ${hostId.slice(0, 8)} -> ${ok ? 'delivered' : 'offline'}`);
    });
    c.on('error', (e) => { log('listen client error', e instanceof Error ? e.message : e); try { c.end(); } catch { /* */ } setTimeout(() => void connect(), 5000); });
    await c.connect();
    await c.query('LISTEN agent_cmd');
    log('listening on agent_cmd');
  };
  await connect();
}

export async function startWsHub(): Promise<void> {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: PORT });

  wss.on('connection', (ws: WebSocket & { isAlive?: boolean; hostId?: string }) => {
    ws.isAlive = true;
    let buffer = '';
    const authTimer = setTimeout(() => { if (!ws.hostId) { try { ws.close(); } catch { /* */ } } }, 10_000);

    ws.on('pong', () => { ws.isAlive = true; if (ws.hostId) void markSeen(ws.hostId); });

    ws.on('message', (data: Buffer) => {
      buffer += data.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        let env: { type?: string; payload?: Record<string, unknown> };
        try { env = JSON.parse(line); } catch { continue; }
        if (env.type === 'hello' && !ws.hostId) {
          void (async () => {
            const token = String(env.payload?.token ?? '');
            const hostId = await authenticate(token);
            if (!hostId) { sendEnv(ws, 'denied'); try { ws.close(); } catch { /* */ } return; }
            clearTimeout(authTimer);
            ws.hostId = hostId;
            const prev = conns.get(hostId);
            if (prev && prev !== ws) { try { prev.close(); } catch { /* */ } }
            conns.set(hostId, ws);
            await markSeen(hostId);
            sendEnv(ws, 'welcome');
            log(`online ${hostId.slice(0, 8)} (${conns.size} connected)`);
          })();
        }
        // agents send nothing else of interest in Phase 1 (reports go over HTTPS as before)
      }
    });

    ws.on('close', () => {
      clearTimeout(authTimer);
      if (ws.hostId && conns.get(ws.hostId) === ws) { conns.delete(ws.hostId); log(`offline ${ws.hostId.slice(0, 8)} (${conns.size} connected)`); }
    });
    ws.on('error', () => { /* close handler cleans up */ });
  });

  // keepalive: drop sockets that stop answering (NAT idle timeouts, dead peers)
  const ping = setInterval(() => {
    for (const ws of wss.clients as Set<WebSocket & { isAlive?: boolean }>) {
      if (ws.isAlive === false) { try { ws.terminate(); } catch { /* */ } continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch { /* */ }
    }
  }, 30_000);
  wss.on('close', () => clearInterval(ping));

  await startListener();
  log(`hub listening on 127.0.0.1:${PORT}`);
}
