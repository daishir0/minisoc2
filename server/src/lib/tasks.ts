// Work items: open KEV / critical findings grouped by what fixes them.
//   OS packages  -> one task per host ("update these packages", reboot if the kernel is involved)
//   dependencies -> one task per (host, system): each package with the version that clears its findings
import { compareVersions } from './cvelookup';
import { q } from './db';

export interface TaskPackage {
  name: string;
  ecosystem: string;
  current: string;
  target: string; // highest "fixed" version needed across its findings ('' if unknown)
  kev: number;
  critical: number;
}

export interface Protected {
  name: string; // system name, OS service, or "all systems on the host"
  systemId?: number;
  exposure: string;
  via: string; // why: service name, runtime, package
  certainty: 'confirmed' | 'estimated';
}

export interface Task {
  key: string; // `${hostId}~${encodeURIComponent(root)}`
  hostId: string;
  host: string;
  osId: string;
  root: string;
  name: string;
  exposure: string;
  kev: number;
  critical: number;
  packages: TaskPackage[];
  reboot: boolean;
  command: string;
  status: 'todo' | 'doing' | 'hold';
  owner: string;
  due: string | null;
  note: string;
  overdue: boolean;
  protects: Protected[]; // systems that this fix protects
}

// The system root is base64url-encoded: a path segment must not contain "/" (or "%2F", which
// web servers such as Apache reject by default).
export const taskKey = (hostId: string, root: string) => `${hostId}~${Buffer.from(root).toString('base64url')}`;
export function parseTaskKey(key: string): { hostId: string; root: string } | null {
  const i = key.indexOf('~');
  if (i < 0) return null;
  const hostId = key.slice(0, i);
  const enc = key.slice(i + 1);
  if (!/^[0-9a-f-]{36}$/.test(hostId) || !/^[A-Za-z0-9_-]+$/.test(enc)) return null;
  return { hostId, root: Buffer.from(enc, 'base64url').toString('utf8') };
}

// OS packages every application on the host depends on.
const HOST_WIDE = /^(kernel|glibc|openssl|openssl-libs|libgcc|libstdc\+\+|systemd|zlib|krb5-libs|sudo|openssh)/;

interface SvcRow { host_id: string; name: string; system_root: string | null; runtime_root: string | null; os_pkg: string | null }
interface SysRow { id: number; host_id: string; root: string; name: string; exposure: string; ignored: boolean }

function protectsFor(t: { hostId: string; root: string; packages: TaskPackage[]; name: string; exposure: string }, svcs: SvcRow[], systems: Map<string, SysRow>): Protected[] {
  const out = new Map<string, Protected>();
  const add = (root: string | null, via: string, certainty: Protected['certainty'], fallbackName?: string) => {
    const sys = root ? systems.get(`${t.hostId}|${root}`) : undefined;
    if (sys?.ignored) return;
    const key = sys ? `s${sys.id}` : `n${fallbackName}`;
    const prev = out.get(key);
    if (prev) {
      if (!prev.via.includes(via)) prev.via += `、${via}`;
      return;
    }
    out.set(key, { name: sys?.name ?? fallbackName ?? root ?? '?', systemId: sys?.id, exposure: sys?.exposure ?? 'unknown', via, certainty });
  };
  const hostSvcs = svcs.filter((x) => x.host_id === t.hostId);
  if (t.root === '__os__') {
    for (const p of t.packages) {
      for (const sv of hostSvcs.filter((x) => x.os_pkg && (p.name === x.os_pkg || p.name.startsWith(`${x.os_pkg}-`)))) {
        add(sv.system_root, `${sv.name.replace(/\.service$/, '')}（${p.name}）`, 'confirmed', sv.system_root ? undefined : `OSのサービス：${sv.name.replace(/\.service$/, '')}`);
      }
    }
    const wide = [...new Set(t.packages.filter((p) => HOST_WIDE.test(p.name)).map((p) => p.name.replace(/^(kernel)[\w-]*$/, '$1')))];
    if (wide.length) out.set('host', { name: 'ホスト上のすべてのシステム', exposure: 'unknown', via: wide.slice(0, 4).join('、'), certainty: 'estimated' });
  } else {
    const users = hostSvcs.filter((x) => x.runtime_root === t.root);
    for (const sv of users) add(sv.system_root, `${sv.name.replace(/\.service$/, '')} が使用`, 'confirmed', sv.system_root ? undefined : sv.name);
    if (!users.length) add(t.root, 'このシステムの依存', 'confirmed', t.name);
  }
  return [...out.values()].sort((a, b) => Number(b.exposure === 'public') - Number(a.exposure === 'public') || a.name.localeCompare(b.name));
}

function pickTarget(fixes: string[]): string {
  const vs = fixes.flatMap((f) => f.split(',').map((x) => x.trim())).filter(Boolean);
  return vs.sort(compareVersions).pop() ?? '';
}

function command(osId: string, root: string, eco: string | null, pkgs: TaskPackage[]): string {
  if (root === '__os__') {
    const names = [...new Set(pkgs.map((p) => p.name.replace(/^(kernel)[\w-]*$/, 'kernel*')))].slice(0, 12).join(' ');
    if (['amzn', 'rhel', 'centos', 'rocky', 'almalinux', 'fedora'].includes(osId)) return `sudo dnf upgrade ${osId === 'amzn' ? '--releasever=latest ' : ''}${names}`;
    if (['debian', 'ubuntu'].includes(osId)) return `sudo apt-get install --only-upgrade ${names}`;
    return names;
  }
  const withT = pkgs.filter((p) => p.target);
  if (eco === 'npm') return `npm install ${withT.map((p) => `${p.name}@${p.target}`).join(' ')}`;
  if (eco === 'PyPI') return `pip install -U ${withT.map((p) => `"${p.name}>=${p.target}"`).join(' ')}`;
  if (eco === 'Packagist') return `composer require ${withT.map((p) => `${p.name}:^${p.target}`).join(' ')}`;
  return withT.map((p) => `${p.name} → ${p.target}`).join(', ');
}

export async function listTasks(opts: { hostId?: string; root?: string } = {}): Promise<Task[]> {
  const params: unknown[] = [];
  let extra = '';
  if (opts.hostId) { params.push(opts.hostId); extra += ` AND f.host_id=$${params.length}`; }
  if (opts.root) { params.push(opts.root); extra += ` AND sys=$${params.length}`; }
  const rows = await q<{
    host_id: string; host: string; os_id: string; root: string; name: string | null; exposure: string | null;
    ecosystem: string; pkg: string; version: string; fixed: string; kev: boolean; severity: string;
  }>(
    `SELECT f.host_id, h.name AS host, h.os_id, sys AS root, s.name, s.exposure, f.ecosystem, f.pkg, f.version, f.fixed, f.kev, f.severity
     FROM findings f JOIN hosts h ON h.id=f.host_id
     CROSS JOIN LATERAL unnest(CASE WHEN cardinality(f.systems)=0 THEN ARRAY['__os__'] ELSE f.systems END) AS sys
     LEFT JOIN systems s ON s.host_id=f.host_id AND s.root=sys
     WHERE f.status='open' AND (f.kev OR f.severity='critical') AND NOT h.disabled AND NOT COALESCE(s.ignored, false) ${extra}`,
    params,
  );
  const state = new Map((await q<{ host_id: string; system_root: string; status: Task['status']; owner: string; due: string | null; note: string }>(
    "SELECT host_id, system_root, status, owner, to_char(due_date, 'YYYY-MM-DD') AS due, note FROM tasks",
  )).map((r) => [taskKey(r.host_id, r.system_root), r]));

  const tasks = new Map<string, Task & { pk: Map<string, TaskPackage & { fixes: string[] }>; ecos: Set<string> }>();
  for (const r of rows) {
    const key = taskKey(r.host_id, r.root);
    const st = state.get(key);
    const t = tasks.get(key) ?? {
      key, hostId: r.host_id, host: r.host, osId: r.os_id, root: r.root, name: r.root === '__os__' ? 'OS' : r.name ?? r.root,
      exposure: r.exposure ?? 'unknown', kev: 0, critical: 0, packages: [], reboot: false, command: '',
      status: st?.status ?? 'todo', owner: st?.owner ?? '', due: st?.due ?? null, note: st?.note ?? '', overdue: false, protects: [],
      pk: new Map(), ecos: new Set<string>(),
    };
    if (r.kev) t.kev++;
    else t.critical++;
    const pkKey = `${r.ecosystem}:${r.pkg}`;
    const p = t.pk.get(pkKey) ?? { name: r.pkg, ecosystem: r.ecosystem, current: r.version.split(',')[0].trim(), target: '', kev: 0, critical: 0, fixes: [] };
    if (r.kev) p.kev++;
    else p.critical++;
    if (r.fixed) p.fixes.push(r.fixed);
    t.pk.set(pkKey, p);
    t.ecos.add(r.ecosystem);
    if (r.root === '__os__' && /^kernel/.test(r.pkg)) t.reboot = true;
    tasks.set(key, t);
  }
  const svcs = await q<SvcRow>('SELECT host_id, name, system_root, runtime_root, os_pkg FROM host_services');
  const systems = new Map((await q<SysRow>('SELECT id, host_id, root, name, exposure, ignored FROM systems')).map((r) => [`${r.host_id}|${r.root}`, r]));
  const today = new Date().toLocaleDateString('sv-SE');
  const out: Task[] = [];
  for (const t of tasks.values()) {
    const packages = [...t.pk.values()].map(({ fixes, ...p }) => ({ ...p, target: pickTarget(fixes) }))
      .sort((a, b) => b.kev - a.kev || b.critical - a.critical || a.name.localeCompare(b.name));
    const eco = t.ecos.size === 1 ? [...t.ecos][0] : null;
    const { pk: _pk, ecos: _ecos, ...rest } = t;
    const protects = protectsFor({ ...rest, packages }, svcs, systems);
    // a fix is as urgent as the most exposed system it protects
    const exposure = protects.some((p) => p.exposure === 'public') ? 'public' : rest.exposure;
    out.push({ ...rest, exposure, packages, protects, command: command(t.osId, t.root, eco, packages), overdue: t.status === 'hold' && !!t.due && t.due < today });
  }
  // KEV first, then public systems, then size
  return out.sort((a, b) => Number(b.kev > 0) - Number(a.kev > 0) || Number(b.exposure === 'public') - Number(a.exposure === 'public') || b.kev - a.kev || b.critical - a.critical);
}

// Open detections that need a human look (not vulnerabilities): intrusion signs and monitoring health.
export async function openDetections(limit = 50) {
  return q<{ id: string; kind: string; severity: string; title: string; detail: string; created_at: Date; host_id: string | null }>(
    `SELECT id, kind, severity, title, detail, created_at, host_id FROM alerts
     WHERE status='open' AND kind IN ('log','state','stale','feed','disk','agent') AND (severity='critical' OR kind IN ('stale','feed','disk'))
     ORDER BY created_at DESC LIMIT $1`,
    [limit],
  );
}

export async function actionBadge(): Promise<number> {
  const tasks = await listTasks();
  const det = await openDetections(200);
  return tasks.filter((t) => t.status !== 'hold' || t.overdue).length + det.length;
}
