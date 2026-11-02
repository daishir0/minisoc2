// minisoc2 worker: background jobs (vulnerability feeds, matching, stale hosts, notifications).
// Runs as its own process: `npm run worker` (systemd unit or docker compose service).
import 'dotenv/config';
import { notifyPending, raiseAlert } from '../src/lib/alerts';
import { q, q1 } from '../src/lib/db';
import { migrate } from './migrate';
import { statfs } from 'node:fs/promises';
import { syncKev } from '../src/lib/feeds';
import { syncSigma } from '../src/lib/sigma';
import { pollPull } from '../src/lib/pullssh';
import { lookupCve } from '../src/lib/cvelookup';
import { dropOldPartitions, ensurePartition } from '../src/lib/logs';
import { matchHost } from '../src/lib/match';
import { recordEvent } from '../src/lib/events';
import { sendDigest } from '../src/lib/digest';
import { NVD_DELAY_MS, nvdStep } from '../src/lib/nvd';
import { getPolicy, getSetting, setSetting } from '../src/lib/settings';
import { startWsHub } from './ws-hub';
import { fetchUbuntuCve, ubuntuVerdict, UBUNTU_CODENAME } from '../src/lib/distro';

const PUBLIC_URL = (process.env.PUBLIC_URL ?? '').replace(/\/+$/, '');
const log = (...a: unknown[]) => console.log(new Date().toISOString(), ...a);
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

async function matchPending() {
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts WHERE needs_match AND NOT disabled ORDER BY last_seen_at');
  for (const h of hosts) {
    const t = Date.now();
    try {
      const r = await matchHost(h.id);
      log(`match ${h.name}: open=${r.open} new=${r.added} resolved=${r.resolved} (${Date.now() - t}ms)`);
    } catch (e) {
      log(`match ${h.name} failed: ${errMsg(e)}`);
    }
  }
}

async function feeds() {
  const kev = await q1<{ last_success: Date | null }>("SELECT last_success FROM feed_status WHERE name='kev'");
  if (!kev?.last_success || Date.now() - kev.last_success.getTime() > 24 * 3600_000) {
    try {
      log(`kev synced: ${await syncKev()} entries`);
      await q("UPDATE hosts SET needs_match=true WHERE NOT disabled AND baseline_done"); // KEV flags may change
    } catch (e) {
      log(`kev sync failed: ${errMsg(e)}`);
    }
  }
  // Stale feeds silently produce false negatives (the Trivy DB lesson), so they are alerts — but the
  // threshold must match each feed's own cadence. Sigma rules are synced weekly, so 48h is a false
  // alarm for it; use a feed-specific staleness window.
  const STALE_HOURS: Record<string, number> = { sigma: 24 * 10 }; // weekly feed → alert only after ~10 days
  const DEFAULT_STALE = 48;
  const label = (h: number) => (h % 24 === 0 ? `${h / 24}日` : `${h}時間`);
  for (const f of await q<{ name: string; last_success: Date | null; last_error: string | null }>('SELECT name, last_success, last_error FROM feed_status')) {
    const h = STALE_HOURS[f.name] ?? DEFAULT_STALE;
    if (f.last_success && Date.now() - f.last_success.getTime() > h * 3600_000) {
      const day = new Date().toISOString().slice(0, 10);
      const title = `脆弱性フィード「${f.name}」が${label(h)}以上更新されていません`;
      if (await raiseAlert({ kind: 'feed', severity: 'high', title, detail: f.last_error ?? '', dedupeKey: `feed:${f.name}:${day}` })) {
        await recordEvent({ kind: 'health', important: true, title });
      }
    }
  }
}

async function pollPullHosts() {
  const due = await q<{ host_id: string; name: string }>(
    `SELECT t.host_id, h.name FROM pull_targets t JOIN hosts h ON h.id=t.host_id
     WHERE NOT h.disabled AND (t.last_poll_at IS NULL OR t.last_poll_at < now() - (t.every_hours || ' hours')::interval)`,
  );
  for (const d of due) {
    try {
      const r = await pollPull(d.host_id);
      log(`pull ${d.name}: ${r.ok ? `packages=${r.packages} logs=${r.logs}` : `failed: ${r.error}`}`);
    } catch (e) {
      log(`pull ${d.name} failed: ${errMsg(e)}`);
    }
  }
}

// Watched CVEs: re-check each against distro/advisory data (fast path, ahead of NVD) and alert the
// moment a host is confirmed affected — including OS/kernel CVEs that only distro trackers map.
async function watchCveAlerts() {
  const cves = await q<{ cve: string }>('SELECT cve FROM watch_cves');
  for (const { cve } of cves) {
    try {
      const v = await lookupCve(cve);
      const crit = (v.external.nvd?.score ?? 0) >= 9 || v.external.nvd?.severity === 'critical';
      for (const h of v.hosts) {
        // Persist distro-tracker OS vulns as a candidate source so they become standing findings on
        // __os__ (not just a one-off alert) — this covers Ubuntu/Debian OS CVEs missing from OSV.
        const desired = h.state === 'affected' ? (h.osVulns ?? []) : [];
        const cur = await q<{ pkg: string; installed: string; fixed: string }>('SELECT pkg, installed, fixed FROM host_distro_cves WHERE host_id=$1 AND vuln_id=$2', [h.hostId, cve]);
        const same = cur.length === desired.length && desired.every((d) => cur.some((c) => c.pkg === d.pkg && c.installed === d.installed && c.fixed === d.fixed));
        if (!same) {
          await q('DELETE FROM host_distro_cves WHERE host_id=$1 AND vuln_id=$2', [h.hostId, cve]);
          for (const d of desired) await q('INSERT INTO host_distro_cves(host_id, vuln_id, pkg, installed, fixed) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING', [h.hostId, cve, d.pkg, d.installed, d.fixed]);
          await q('UPDATE hosts SET needs_match=true WHERE id=$1 AND NOT disabled', [h.hostId]);
        }
        if (h.state !== 'affected') continue;
        if (await raiseAlert({
          kind: 'watch', severity: crit ? 'critical' : 'high', hostId: h.hostId,
          title: `[${h.host}] 監視中の ${cve} に影響あり（配布元勧告で確認）`,
          detail: h.reasons.slice(0, 3).join('\n'),
          dedupeKey: `watch-distro:${cve}:${h.hostId}`,
        })) {
          await recordEvent({ hostId: h.hostId, kind: 'vuln_new', important: true, title: `${h.host}：監視中の ${cve} に影響あり（配布元勧告）` });
        }
      }
    } catch (e) {
      log(`watch lookup ${cve} failed: ${errMsg(e)}`);
    }
  }
}

// Ubuntu/Debian OS CVEs from OSV often lack a fixed version → shown as open even when already patched.
// Consult the vendor tracker (authority) and record CVEs confirmed FIXED on the host so matching can
// suppress those OSV false positives. Only "already fixed" is recorded; genuinely-vulnerable stay.
async function syncUbuntuOs() {
  const hosts = await q<{ id: string; os_version: string }>("SELECT id, os_version FROM hosts WHERE os_id IN ('ubuntu','debian') AND NOT disabled AND baseline_done");
  const cache = new Map<string, Awaited<ReturnType<typeof fetchUbuntuCve>>>();
  for (const h of hosts) {
    const codename = UBUNTU_CODENAME[h.os_version];
    if (!codename) continue;
    const osPkgs = await q<{ name: string; version: string }>("SELECT name, version FROM host_packages WHERE host_id=$1 AND ecosystem LIKE 'Ubuntu:%'", [h.id]);
    if (!osPkgs.length) continue;
    const cves = await q<{ vuln_id: string }>("SELECT DISTINCT vuln_id FROM findings WHERE host_id=$1 AND status='open' AND ecosystem LIKE 'Ubuntu:%' AND '__os__' = ANY(systems)", [h.id]);
    const fixed: string[] = [];
    for (const { vuln_id } of cves) {
      const cve = vuln_id.replace(/^(UBUNTU|DEBIAN)-/, '');
      if (!/^CVE-\d{4}-\d+$/.test(cve)) continue;
      if (!cache.has(cve)) { cache.set(cve, await fetchUbuntuCve(cve)); await new Promise((r) => setTimeout(r, 150)); }
      const uc = cache.get(cve);
      if (!uc) continue;
      const v = ubuntuVerdict(codename, osPkgs, uc);
      if (v.matched && !v.red.length && v.green.length) fixed.push(vuln_id); // vendor says fixed at <= installed
    }
    const cur = (await q<{ vuln_id: string }>('SELECT vuln_id FROM host_os_fixed WHERE host_id=$1', [h.id])).map((r) => r.vuln_id);
    const same = cur.length === fixed.length && fixed.every((x) => cur.includes(x));
    if (!same) {
      await q('DELETE FROM host_os_fixed WHERE host_id=$1', [h.id]);
      for (const vid of fixed) await q('INSERT INTO host_os_fixed(host_id, vuln_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [h.id, vid]);
      await q('UPDATE hosts SET needs_match=true WHERE id=$1', [h.id]);
      log(`ubuntu-os ${h.id.slice(0, 8)}: ${fixed.length} OS CVE already-fixed per vendor (suppressing OSV false positives)`);
    }
  }
}

async function sigmaSync() {
  const f = await q1<{ last_success: Date | null }>("SELECT last_success FROM feed_status WHERE name='sigma'");
  if (f?.last_success && Date.now() - f.last_success.getTime() < 7 * 24 * 3600_000) return;
  try {
    const r = await syncSigma();
    log(`sigma synced: ${r.kept} rules compiled of ${r.total} linux rules`);
  } catch (e) {
    log(`sigma sync failed: ${errMsg(e)}`);
  }
}

async function dailyRematch() {
  const policy = await getPolicy();
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const last = await getSetting<{ date: string }>('last_full_rematch', { date: '' });
  if (now.getHours() >= policy.fullRematchHour && last.date !== today) {
    await q('UPDATE hosts SET needs_match=true WHERE NOT disabled AND baseline_done');
    await setSetting('last_full_rematch', { date: today });
    log('daily re-match of all hosts scheduled');
  }
}

async function staleHosts() {
  const policy = await getPolicy();
  const rows = await q<{ id: string; name: string; last_seen_at: Date | null }>(
    `UPDATE hosts SET stale_alerted=true
     WHERE NOT disabled AND NOT stale_alerted AND COALESCE(last_seen_at, enrolled_at) < now() - ($1 || ' hours')::interval
     RETURNING id, name, last_seen_at`,
    [String(policy.staleHours)],
  );
  for (const h of rows) {
    await recordEvent({ hostId: h.id, kind: 'health', important: true, title: `${h.name}：${policy.staleHours}時間以上報告がありません` });
    await raiseAlert({
      kind: 'stale', severity: 'high', hostId: h.id,
      title: `[${h.name}] ${policy.staleHours}時間以上報告がありません`,
      detail: `最終報告：${h.last_seen_at?.toLocaleString('ja-JP') ?? 'なし'}。エージェントの停止、定期実行の解除、サーバーへの通信不可などが考えられます。`,
      dedupeKey: `stale:${h.id}:${h.last_seen_at?.toISOString() ?? 'never'}`,
    });
  }
}

// Daily summary mail at the configured hour (once per day).
async function digest() {
  const policy = await getPolicy();
  if (policy.digestHour < 0) return;
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const last = await getSetting<{ date: string; at?: string }>('last_digest', { date: '' });
  if (now.getHours() < policy.digestHour || last.date === today) return;
  const since = last.at ? new Date(last.at) : new Date(Date.now() - 86400_000);
  const r = await sendDigest(since);
  await setSetting('last_digest', { date: today, at: now.toISOString() });
  log(`digest: ${r}`);
}

async function housekeeping() {
  await q("DELETE FROM change_events WHERE ts < now() - interval '180 days'");
  await q("DELETE FROM reports WHERE received_at < now() - interval '180 days'");
  await q("DELETE FROM log_batches WHERE received_at < now() - interval '180 days'");
  await q('DELETE FROM sessions WHERE expires_at < now()');
}

// Raw logs: drop partitions past the retention period and pre-create tomorrow's.
async function logRetention() {
  const policy = await getPolicy();
  const dropped = await dropOldPartitions(policy.logRetentionDays);
  if (dropped.length) log(`dropped raw log partitions: ${dropped.join(', ')}`);
  await q("DELETE FROM log_hits WHERE ts < now() - ($1 || ' days')::interval", [String(Math.max(policy.logRetentionDays, 90))]);
  await ensurePartition(new Date(Date.now() + 86400_000).toISOString().slice(0, 10));
}

// Disk guard: above the threshold, raw logs are not stored (rules and aggregates keep running).
async function diskGuard() {
  const policy = await getPolicy();
  const st = await statfs(process.env.DISK_GUARD_PATH || '/');
  const used = Math.round(100 * (1 - st.bavail / st.blocks));
  const cur = await getSetting<{ paused: boolean }>('raw_ingest', { paused: false });
  const paused = used >= policy.diskGuardPercent;
  if (paused !== cur.paused) {
    await setSetting('raw_ingest', { paused, used, at: new Date().toISOString() });
    await raiseAlert({
      kind: 'disk', severity: paused ? 'high' : 'info',
      title: paused ? `ディスク使用率 ${used}% のため生ログの保存を停止しました` : `ディスク使用率 ${used}% に下がったため生ログの保存を再開しました`,
      detail: `上限 ${policy.diskGuardPercent}%（設定で変更できます）。ルール判定と集計は続けています。`,
      dedupeKey: `disk:${paused}:${new Date().toISOString().slice(0, 13)}`,
    });
    await recordEvent({ kind: 'health', important: paused, title: paused ? `ディスク使用率 ${used}% のため生ログの保存を停止` : `ディスク使用率 ${used}% で生ログの保存を再開` });
    log(`disk guard: used=${used}% paused=${paused}`);
  }
}

// Once a day: sources and rules whose volume yesterday was 3x+ their 7-day average.
async function logSpikes() {
  const y = new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
  const last = await getSetting<{ day: string }>('last_spike_check', { day: '' });
  if (last.day === y) return;
  const spikes = await q<{ host_id: string; name: string; key: string; n: string; avg: string }>(
    `WITH t AS (
       SELECT host_id, 'source:' || source AS key, day, lines AS n FROM log_daily WHERE day BETWEEN $1::date - 7 AND $1::date
       UNION ALL
       SELECT host_id, 'rule:' || rule_id, day, hits FROM log_rule_daily WHERE day BETWEEN $1::date - 7 AND $1::date
     )
     SELECT t.host_id, h.name, t.key, max(n) FILTER (WHERE day = $1::date) AS n, avg(n) FILTER (WHERE day < $1::date) AS avg
     FROM t JOIN hosts h ON h.id=t.host_id GROUP BY t.host_id, h.name, t.key
     HAVING count(*) FILTER (WHERE day < $1::date) >= 3
        AND max(n) FILTER (WHERE day = $1::date) >= 3 * avg(n) FILTER (WHERE day < $1::date)
        AND max(n) FILTER (WHERE day = $1::date) >= 100`,
    [y],
  );
  for (const s of spikes) {
    await raiseAlert({
      kind: 'log', severity: 'medium', hostId: s.host_id,
      title: `[${s.name}] ログ量が平常の${(Number(s.n) / Math.max(1, Number(s.avg))).toFixed(1)}倍：${s.key}`,
      detail: `${y}: ${s.n}件（直近7日平均 ${Math.round(Number(s.avg))}件）`,
      dedupeKey: `spike:${s.host_id}:${s.key}:${y}`,
    });
  }
  await setSetting('last_spike_check', { day: y });
  if (spikes.length) log(`log spikes: ${spikes.length}`);
}

async function tick(n: number) {
  const steps: [string, () => Promise<unknown>, number][] = [
    ['matchPending', matchPending, 1],
    ['staleHosts', staleHosts, 5],
    ['feeds', feeds, 10],
    ['sigmaSync', sigmaSync, 60],
    ['syncUbuntuOs', syncUbuntuOs, 60],
    ['watchCveAlerts', watchCveAlerts, 30],
    ['pollPullHosts', pollPullHosts, 5],
    ['dailyRematch', dailyRematch, 10],
    ['notify', async () => {
      const r = await notifyPending(PUBLIC_URL);
      if (r.sent || r.error) log(`notify: sent=${r.sent} skipped=${r.skipped}${r.error ? ' error=' + r.error : ''}`);
    }, 1],
    ['housekeeping', housekeeping, 360],
    ['logRetention', logRetention, 60],
    ['diskGuard', diskGuard, 10],
    ['logSpikes', logSpikes, 30],
    ['digest', digest, 5],
  ];
  for (const [name, fn, every] of steps) {
    if (n % every !== 0) continue;
    try {
      await fn();
    } catch (e) {
      log(`${name} failed: ${errMsg(e)}`);
    }
  }
}

async function main() {
  const applied = await migrate();
  if (applied.length) log(`migrations applied: ${applied.join(', ')}`);
  try { await startWsHub(); } catch (e) { log(`ws hub failed to start: ${errMsg(e)}`); }
  log('worker started');
  let n = 0;
  let stopping = false;
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => { stopping = true; });
  // NVD backfill / incremental runs beside the regular jobs (requests can take a minute each)
  void (async () => {
    let pages = 0;
    while (!stopping) {
      let more = false;
      try {
        more = await nvdStep();
      } catch (e) {
        log(`nvd failed: ${errMsg(e)}`);
      }
      if (more && ++pages % 10 === 0) {
        await q('UPDATE hosts SET needs_match=true WHERE NOT disabled AND baseline_done'); // pick up new scores
        log(`nvd: ${pages} pages synced`);
      }
      for (let i = 0; i < (more ? NVD_DELAY_MS : 600_000) / 1000 && !stopping; i++) await new Promise((r) => setTimeout(r, 1000));
    }
  })();
  while (!stopping) {
    await tick(n++);
    for (let i = 0; i < 60 && !stopping; i++) await new Promise((r) => setTimeout(r, 1000));
  }
  log('worker stopped');
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
