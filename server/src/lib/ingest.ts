import { randomUUID } from 'node:crypto';
import { raiseAlert } from './alerts';
import { q, q1, tx } from './db';
import type { HostState, Report } from './payload';
import { randomToken, safeEqual, sha256hex } from './secrets';
import { defaultName, excludedBy, globToRegExp, OS_SYSTEM, serviceOsPackage, serviceRuntime, serviceSystem, systemOf } from './systems';
import { ipAllowed } from './ipallow';
import { getPolicy } from './settings';
import { recordEvent } from './events';
import { ingestFiles } from './fileintegrity';

export interface HostRow {
  id: string;
  name: string;
  hostname: string;
  baseline_done: boolean;
  disabled: boolean;
  state: HostState | Record<string, never>;
  system_roots: string[];
  allowed_ips: string[];
}

// Host tokens look like "<hostId>.<secret>"; only the hash of the whole token is stored.
export async function authenticateHost(authHeader: string | null): Promise<HostRow | null> {
  const token = authHeader?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token) return null;
  const id = token.split('.')[0];
  if (!/^[0-9a-f-]{36}$/.test(id)) return null;
  const h = await q1<HostRow & { token_hash: string }>('SELECT id, name, hostname, baseline_done, disabled, state, system_roots, allowed_ips, token_hash FROM hosts WHERE id=$1', [id]);
  if (!h || h.disabled || !safeEqual(h.token_hash, sha256hex(token))) return null;
  return h;
}

// A host's own allow list wins; an empty one falls back to the global default. Empty both = allow.
export async function hostIpAllowed(host: HostRow, ip: string): Promise<boolean> {
  const list = host.allowed_ips?.length ? host.allowed_ips : (await getPolicy()).defaultAllowedIps;
  return ipAllowed(ip, list);
}

// Enrollment has no host yet, so only the global default applies.
export async function enrollIpAllowed(ip: string): Promise<boolean> {
  return ipAllowed(ip, (await getPolicy()).defaultAllowedIps);
}

export async function enroll(token: string, hostname: string, platform: string, agentVersion: string): Promise<{ hostId: string; hostToken: string } | null> {
  return tx(async (c) => {
    const r = await c.query(
      'UPDATE enroll_tokens SET uses = uses + 1 WHERE token_hash=$1 AND uses < max_uses AND expires_at > now() RETURNING id',
      [sha256hex(token)],
    );
    if (!r.rowCount) return null;
    const hostId = randomUUID();
    const hostToken = `${hostId}.${randomToken()}`;
    const name = hostname.slice(0, 200) || 'unnamed';
    await c.query(
      'INSERT INTO hosts(id, name, hostname, token_hash, platform, agent_version) VALUES ($1,$2,$2,$3,$4,$5)',
      [hostId, name, sha256hex(hostToken), platform.slice(0, 40), agentVersion.slice(0, 40)],
    );
    return { hostId, hostToken };
  });
}

function stateDiff(host: HostRow, next: HostState): { severity: 'critical' | 'high' | 'medium'; title: string; detail: string; key: string }[] {
  const prev = host.state as Partial<HostState>;
  if (!prev.ports) return [];
  const out: { severity: 'critical' | 'high' | 'medium'; title: string; detail: string; key: string }[] = [];
  const pk = (p: { proto: string; addr: string; port: number }) => `${p.proto} ${p.addr}:${p.port}`;
  const before = new Set(prev.ports.map(pk));
  const added = next.ports.filter((p) => !before.has(pk(p)) && !p.proto.startsWith('udp'));
  if (added.length) {
    const exposed = added.some((p) => p.addr === '0.0.0.0' || p.addr === '::');
    out.push({
      severity: exposed ? 'high' : 'medium',
      title: `新しい待受ポート${exposed ? '（外部公開）' : ''}：${added.map((p) => p.port).join(', ')}`,
      detail: added.map(pk).join('\n'),
      key: `ports:${added.map(pk).sort().join(',')}`,
    });
  }
  const newUsers = next.users.filter((u) => !(prev.users ?? []).includes(u));
  if (newUsers.length) out.push({ severity: 'critical', title: `ログイン可能なアカウントが増えました：${newUsers.join(', ')}`, detail: '', key: `users:${newUsers.sort().join(',')}` });
  for (const [file, hash] of Object.entries(next.fileHashes)) {
    const old = prev.fileHashes?.[file];
    if (old && old !== hash) {
      // a new SSH key or sudo rule is an intrusion sign; other watched files are detail-level
      const critical = /authorized_keys|sudoers|Administrators group/.test(file);
      out.push({ severity: critical ? 'critical' : 'medium', title: `監視ファイルが変更されました：${file}`, detail: `${old.slice(0, 12)} -> ${hash.slice(0, 12)}`, key: `file:${file}:${hash}` });
    }
  }
  return out;
}

export async function ingestReport(host: HostRow, r: Report): Promise<{ packages: number; advisories: number | null }> {
  // Collapse duplicates (the same npm package appears in many lockfiles).
  const pkgs = new Map<string, { ecosystem: string; name: string; version: string; sources: Set<string>; systems: Set<string> }>();
  const scanPaths = Array.isArray(r.scanPaths) ? r.scanPaths : [];
  const pythonEnvs = Array.isArray(r.pythonEnvs) ? r.pythonEnvs.map(String) : [];
  // manually registered systems decide the grouping (longest root wins)
  const manualRoots = (await q<{ root: string }>("SELECT root FROM systems WHERE host_id=$1 AND origin='manual' AND root <> '__os__'", [host.id])).map((x) => x.root);
  const roots = [...new Set([...(host.system_roots ?? []), ...manualRoots])];
  // intentionally vulnerable paths inside systems (test corpora etc.) are set aside, not matched
  const exRules = new Map<string, { pattern: string; re: RegExp }[]>();
  for (const r of await q<{ root: string; pattern: string }>('SELECT s.root, e.pattern FROM system_excludes e JOIN systems s ON s.id=e.system_id WHERE s.host_id=$1', [host.id])) {
    exRules.set(r.root, [...(exRules.get(r.root) ?? []), { pattern: r.pattern, re: globToRegExp(r.pattern) }]);
  }
  const excluded = new Map<string, { root: string; pattern: string; ecosystem: string; name: string; version: string }>();
  const clean = (x: unknown) => String(x ?? '').replace(/\u0000/g, '').slice(0, 500); // Postgres text rejects NUL
  for (const raw of r.packages) {
    const p = { ecosystem: clean(raw.ecosystem), name: clean(raw.name), version: clean(raw.version), source: clean(raw.source) };
    if (!p.name || !p.version) continue;
    const k = `${p.ecosystem}\u0000${p.name}\u0000${p.version}`;
    const e = pkgs.get(k) ?? { ecosystem: p.ecosystem, name: p.name, version: p.version, sources: new Set<string>(), systems: new Set<string>() };
    const sys = systemOf(p.source, scanPaths, roots, pythonEnvs);
    const ex = exRules.has(sys) ? excludedBy(p.source, sys, exRules.get(sys)!) : null;
    if (ex) {
      excluded.set(`${sys}\u0001${ex}\u0001${k}`, { root: sys, pattern: ex, ecosystem: p.ecosystem, name: p.name, version: p.version });
      if (!pkgs.has(k)) continue;
    } else {
      if (e.sources.size < 5) e.sources.add(p.source);
      e.systems.add(sys);
    }
    pkgs.set(k, e);
  }
  // packages seen only under excluded paths are not part of the inventory
  for (const [k, e] of pkgs) if (!e.systems.size) pkgs.delete(k);
  const allSystems = new Set<string>();
  for (const e of pkgs.values()) e.systems.forEach((x) => allSystems.add(x));
  // services link applications to shared runtimes and OS packages; an application without any
  // lockfile still becomes a system through its service (e.g. a FastAPI app on a conda env)
  const services = (Array.isArray(r.services) ? r.services : []).slice(0, 500).map((sv) => {
    const sysRoot = serviceSystem(clean(sv.cwd), scanPaths, roots);
    return {
      name: clean(sv.name).slice(0, 200), cwd: clean(sv.cwd), bin: clean(sv.bin), user: clean(sv.user).slice(0, 64),
      systemRoot: sysRoot, runtimeRoot: serviceRuntime(clean(sv.bin), sv.condaEnv ? clean(sv.condaEnv) : undefined, pythonEnvs, sysRoot),
      osPkg: serviceOsPackage(sv.execPkg ? clean(sv.execPkg) : undefined),
    };
  });
  for (const sv of services) if (sv.systemRoot) allSystems.add(sv.systemRoot);
  // directories holding a project marker (package.json, composer.json, go.mod ...) become candidate
  // projects too, so a lock-less app is still detected. The sentinel makes systemOf group to the root.
  for (const d of Array.isArray(r.projectDirs) ? r.projectDirs : []) {
    const root = systemOf(`${clean(d)}/package.json`, scanPaths, roots, pythonEnvs);
    if (root && root !== OS_SYSTEM) allSystems.add(root);
  }
  const diffs = host.baseline_done ? stateDiff(host, r.state) : [];

  await tx(async (c) => {
    await c.query(
      `UPDATE hosts SET hostname=$2, platform=$3, os_name=$4, os_version=$5, os_id=$6, kernel=$7, arch=$8, agent_version=$9,
         last_seen_at=now(), stale_alerted=false, needs_match=true, state=$10 WHERE id=$1`,
      [host.id, r.host.hostname, r.host.platform, r.host.osName, r.host.osVersion, r.host.osId, r.host.kernel, r.host.arch, r.agentVersion, JSON.stringify(r.state)],
    );
    await c.query('DELETE FROM host_packages WHERE host_id=$1', [host.id]);
    const rows = [...pkgs.values()];
    for (let i = 0; i < rows.length; i += 2000) {
      const chunk = rows.slice(i, i + 2000);
      await c.query(
        `INSERT INTO host_packages(host_id, ecosystem, name, version, sources, systems)
         SELECT $1, e, n, v, string_to_array(s, E'\\x1f'), string_to_array(y, E'\\x1f') FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) AS t(e, n, v, s, y)`,
        [host.id, chunk.map((x) => x.ecosystem), chunk.map((x) => x.name), chunk.map((x) => x.version), chunk.map((x) => [...x.sources].join('\x1f')), chunk.map((x) => [...x.systems].join('\x1f'))],
      );
    }
    if (Array.isArray(r.services)) {
      await c.query('DELETE FROM host_services WHERE host_id=$1', [host.id]);
      if (services.length) {
        await c.query(
          `INSERT INTO host_services(host_id, name, cwd, bin, run_user, system_root, runtime_root, os_pkg)
           SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[]) ON CONFLICT DO NOTHING`,
          [host.id, services.map((x) => x.name), services.map((x) => x.cwd), services.map((x) => x.bin), services.map((x) => x.user),
            services.map((x) => x.systemRoot), services.map((x) => x.runtimeRoot), services.map((x) => x.osPkg)],
        );
      }
    }
    await c.query('DELETE FROM host_packages_excluded WHERE host_id=$1', [host.id]);
    const exRows = [...excluded.values()];
    for (let i = 0; i < exRows.length; i += 5000) {
      const ch = exRows.slice(i, i + 5000);
      await c.query(
        `INSERT INTO host_packages_excluded(host_id, system_root, pattern, ecosystem, name, version)
         SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) ON CONFLICT DO NOTHING`,
        [host.id, ch.map((x) => x.root), ch.map((x) => x.pattern), ch.map((x) => x.ecosystem), ch.map((x) => x.name), ch.map((x) => x.version)],
      );
    }
    const sys = [...allSystems];
    if (sys.length) {
      await c.query(
        `INSERT INTO systems(host_id, root, name) SELECT $1, r, n FROM unnest($2::text[], $3::text[]) AS t(r, n)
         ON CONFLICT (host_id, root) DO UPDATE SET last_seen=now()`,
        [host.id, sys, sys.map((x) => defaultName(x, pythonEnvs))],
      );
    }
    // auto-detected systems that no longer exist and were never edited go away
    const stale = await c.query<{ id: number; root: string; name: string }>(
      `SELECT id, root, name FROM systems WHERE host_id=$1 AND origin='auto' AND NOT ignored AND NOT (root = ANY($2::text[]))
         AND exposure='unknown' AND criticality='normal' AND url='' AND owner='' AND note='' AND stack=''`,
      [host.id, sys],
    );
    const drop = stale.rows.filter((x) => x.name === defaultName(x.root, pythonEnvs)).map((x) => x.id);
    if (drop.length) await c.query('DELETE FROM systems WHERE id = ANY($1::int[])', [drop]);
    if (r.osAdvisories) {
      await c.query('DELETE FROM host_os_advisories WHERE host_id=$1', [host.id]);
      const adv = new Map(r.osAdvisories.map((a) => ({ id: clean(a.id), advisory: a.advisory ? clean(a.advisory) : undefined, severity: clean(a.severity), pkg: clean(a.pkg), fixed: clean(a.fixed) })).map((a) => [`${a.id}\u0001${a.pkg}`, a])); // last (newest fix) wins
      const list = [...adv.values()];
      for (let i = 0; i < list.length; i += 2000) {
        const chunk = list.slice(i, i + 2000);
        await c.query(
          `INSERT INTO host_os_advisories(host_id, vuln_id, advisory, severity, pkg, fixed)
           SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])`,
          [host.id, chunk.map((a) => a.id), chunk.map((a) => a.advisory ?? null), chunk.map((a) => a.severity), chunk.map((a) => a.pkg), chunk.map((a) => a.fixed)],
        );
      }
    }
    if (Array.isArray(r.osFixed)) {
      await c.query('DELETE FROM host_fixed_cves WHERE host_id=$1', [host.id]);
      const fixed = [...new Map(r.osFixed.map((a) => ({ id: clean(a.id), severity: clean(a.severity), pkg: clean(a.pkg), fixed: clean(a.fixed) })).map((a) => [`${a.id}\u0001${a.pkg}`, a])).values()];
      for (let i = 0; i < fixed.length; i += 5000) {
        const ch = fixed.slice(i, i + 5000);
        await c.query(
          `INSERT INTO host_fixed_cves(host_id, vuln_id, severity, pkg, fixed) SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[])`,
          [host.id, ch.map((a) => a.id), ch.map((a) => a.severity), ch.map((a) => a.pkg), ch.map((a) => a.fixed)],
        );
      }
    }
    await c.query(
      'INSERT INTO reports(host_id, agent_version, duration_ms, package_count, advisory_count, errors, update_info) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [host.id, r.agentVersion, Math.round(r.durationMs), pkgs.size, r.osAdvisories?.length ?? null, JSON.stringify(r.errors.slice(0, 50)), JSON.stringify(r.update ?? null)],
    );
  });

  for (const d of diffs) {
    await recordEvent({ hostId: host.id, kind: 'host_state', important: d.severity === 'critical', title: `${host.name}：${d.title}`, detail: d.detail });
    await raiseAlert({ kind: 'state', severity: d.severity, hostId: host.id, title: `[${host.name}] ${d.title}`, detail: d.detail, dedupeKey: `state:${host.id}:${d.key}` });
  }
  if (r.update?.error) {
    await raiseAlert({ kind: 'agent', severity: 'medium', hostId: host.id, title: `[${host.name}] エージェントの自己更新に失敗`, detail: r.update.error, dedupeKey: `update:${host.id}:${r.update.latest}:${r.update.error}` });
  }
  await ingestFiles(host, r.files, !!r.filesTruncated);
  return { packages: pkgs.size, advisories: r.osAdvisories?.length ?? null };
}

export async function hostCount(): Promise<number> {
  return Number((await q<{ n: string }>('SELECT count(*) AS n FROM hosts'))[0].n);
}
