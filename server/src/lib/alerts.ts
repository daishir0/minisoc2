import { q, q1 } from './db';
import { sendMail } from './mail';
import { getMail, getPolicy, type PolicySettings } from './settings';
import { atLeast, sevInSql } from './severity';
import { CVE_SELECT, CVE_JOIN, cveScore, cveSort, groupByCve, type CveRow } from './mailfmt';

const nul = (x: string) => x.replace(/\u0000/g, '|'); // Postgres text rejects NUL

export interface NewAlert {
  kind: 'vuln' | 'kev' | 'watch' | 'stale' | 'feed' | 'baseline' | 'agent' | 'state' | 'log' | 'disk';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  hostId?: string | null;
  title: string;
  detail?: string;
  dedupeKey: string;
}

// Idempotent: the same dedupe key never creates a second alert.
export async function raiseAlert(a: NewAlert): Promise<boolean> {
  const r = await q1<{ id: string }>(
    `INSERT INTO alerts(kind, severity, host_id, title, detail, dedupe_key) VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (dedupe_key) DO NOTHING RETURNING id`,
    [a.kind, a.severity, a.hostId ?? null, nul(a.title).slice(0, 500), nul(a.detail ?? '').slice(0, 10000), nul(a.dedupeKey).slice(0, 1000)],
  );
  return !!r;
}

// What gets emailed immediately = the "Act now" bucket, to stop the flood of ordinary critical vulns.
// - KEV, watched CVEs, host/feed/disk health, baselines, info: always immediate (curated / low volume).
// - Non-vuln critical (intrusion-ish state/log/agent): immediate.
// - Plain `vuln` findings: immediate ONLY when exploit probability is high (EPSS >= ACT_EPSS). Everything
//   else goes to the daily digest. This is what cuts the hundreds of low-EPSS critical-CVE mails.
const IMMEDIATE_KINDS = new Set(['kev', 'stale', 'feed', 'disk', 'baseline']);
const ACT_EPSS = 0.5;

// Resolve the EPSS score of a `vuln` alert from the CVE embedded in its dedupe key
// (`vuln:<hostId>:<vulnId>|<ecosystem>|<pkg>:<ts>`). Returns null when unknown.
async function vulnEpss(dedupeKey: string): Promise<number | null> {
  const m = /^vuln:[0-9a-f-]+:([^|]+)\|/.exec(dedupeKey);
  if (!m) return null;
  const vid = m[1];
  const cve = vid.replace(/^(UBUNTU|DEBIAN)-/, '');
  const r = await q1<{ s: number | null }>(
    'SELECT max(e.score) AS s FROM epss e WHERE e.cve=$1 OR e.cve = ANY(SELECT unnest(aliases) FROM vulns v WHERE v.id=$2)', [cve, vid]);
  return r?.s ?? null;
}

async function immediate(a: { kind: string; severity: string; dedupe_key: string }, policy: PolicySettings): Promise<boolean> {
  // Traffic blackout (an established site served 0 requests): an availability/silence signal, not an
  // intrusion. It stays an open alert (counted in the daily digest and on the host page) but never fires
  // an immediate "threat detected" mail — the quiet, low-urgency case belongs in the daily summary.
  if (a.dedupe_key.startsWith('web-gap:')) return false;
  if (a.kind === 'vuln') { const e = await vulnEpss(a.dedupe_key); return (e != null && e >= ACT_EPSS) || atLeast(a.severity, policy.mailLevel); }
  if (a.kind === 'watch') {
    if (policy.watchAlwaysImmediate) return true;
    if (/^watch-(fixable|upstream-fix)/.test(a.dedupe_key)) return true; // a published fix → always tell now
    return atLeast(a.severity, policy.mailLevel); // a mere detection follows the mail line
  }
  return IMMEDIATE_KINDS.has(a.kind) || a.severity === 'critical' || a.severity === 'info';
}

// --- immediate-notification wording ------------------------------------------------------------------
// Every immediate mail has a self-explanatory subject "即時通知：<なぜ今届いたか>", a one-sentence plain
// description of the situation, and a link to the page where the reader can act right now. Intrusion /
// monitoring events ("今すぐ人が見るべき") go one-per-event so they are never buried; vulnerability and
// watched-CVE detections ("情報・対応は順次") are each batched into a single mail.
interface PendingAlert { id: string; kind: string; severity: string; title: string; detail: string; created_at: Date; host_id: string | null; host_name: string | null; dedupe_key: string }
type Mail = { subject: string; body: string };

const URGENT_KINDS = new Set(['state', 'log', 'stale', 'feed', 'disk', 'agent', 'baseline']);
const stripHost = (t: string) => t.replace(/^\[[^\]]+\]\s*/, '').replace(/\s+/g, ' ').trim();
const cveOf = (t: string) => (t.match(/CVE-\d{4}-\d+/) ?? ['CVE不明'])[0];

// Subject tail (the reason) and the opening sentence, per urgent kind.
function urgentWording(host: string, kind: string): { reason: string; sentence: string; actsOnHost: boolean } {
  switch (kind) {
    case 'state': return { reason: `${host} で侵入の兆候を検出`, sentence: `${host} でホスト状態の重大な変化（侵入の兆候）を検出しました。`, actsOnHost: true };
    case 'log': return { reason: `${host} で侵入の兆候を検出`, sentence: `${host} でログ上の脅威（侵入の兆候）を検出しました。`, actsOnHost: true };
    case 'stale': return { reason: `${host} からの報告が停止`, sentence: `${host} からの定期報告が途絶えています。`, actsOnHost: true };
    case 'disk': return { reason: `${host} でディスク逼迫`, sentence: `${host} のディスク使用率が上限を超えました（生ログの保存を停止している可能性）。`, actsOnHost: true };
    case 'agent': return { reason: `${host} でエージェントの異常`, sentence: `${host} のエージェントに異常が発生しました。`, actsOnHost: true };
    case 'baseline': return { reason: `${host} の監視基準線を確立`, sentence: `${host} の監視基準線（ベースライン）を確立しました。`, actsOnHost: true };
    case 'feed': return { reason: `脅威フィードの異常`, sentence: `脅威情報フィードの取得に問題が発生しました（検知の鮮度に影響する可能性）。`, actsOnHost: false };
    default: return { reason: `${host} で要確認の事象`, sentence: `${host} で要確認の事象が発生しました。`, actsOnHost: false };
  }
}
const KIND_LABEL: Record<string, string> = { state: 'ホスト状態の変化', log: 'ログ脅威', stale: '報告停止', disk: 'ディスク逼迫', agent: 'エージェント異常', baseline: '基準線', feed: '脅威フィード' };

export type VulnRow = CveRow & { host_id: string; host: string };

// Build the immediate-notification mails from the alerts that passed the immediacy filter. Pure (no I/O):
// the vulnerability findings are fetched by the caller and passed in, so this is unit-testable.
export function buildImmediateMails(toSend: PendingAlert[], vulnRows: VulnRow[], publicUrl: string): Mail[] {
  const url = publicUrl.replace(/\/+$/, '');
  const mails: Mail[] = [];
  const hostOf = (a: PendingAlert) => a.host_name ?? '(ホスト不明)';

  // 1) urgent events: group by host × kind → one mail per group (capped; overflow folds into one summary)
  const urgent = toSend.filter((a) => URGENT_KINDS.has(a.kind));
  const groups = new Map<string, { host: string; host_id: string | null; kind: string; items: PendingAlert[] }>();
  for (const a of urgent) {
    const key = `${hostOf(a)}|${a.kind}`;
    const g = groups.get(key) ?? { host: hostOf(a), host_id: a.host_id, kind: a.kind, items: [] };
    g.items.push(a); groups.set(key, g);
  }
  const groupList = [...groups.values()];
  if (groupList.length > 6) {
    // too many at once (e.g. a network blip stales many hosts): one consolidated urgent mail
    const lines = ['至急の確認が必要な事象が発生しました。', ''];
    for (const g of groupList) {
      const w = urgentWording(g.host, g.kind);
      const t = stripHost(g.items[g.items.length - 1].title);
      lines.push(`・${g.host}　${KIND_LABEL[g.kind] ?? g.kind}${g.items.length > 1 ? ` ×${g.items.length}` : ''}${t ? `：${t.length > 72 ? t.slice(0, 72) + '…' : t}` : ''}`);
      lines.push(`   ▶ ${w.actsOnHost && g.host_id ? `${url}/hosts/${g.host_id}` : `${url}/`}`);
    }
    mails.push({ subject: `即時通知：要確認の事象 ${groupList.length}件`, body: lines.join('\n') });
  } else {
    for (const g of groupList) {
      const w = urgentWording(g.host, g.kind);
      const t = stripHost(g.items[g.items.length - 1].title);
      const n = g.items.length;
      const act = w.actsOnHost && g.host_id ? `▶ 今すぐ確認して対応 ${url}/hosts/${g.host_id}` : `▶ 詳細 ${url}/`;
      const body = [
        w.sentence,
        `内容：${KIND_LABEL[g.kind] ?? g.kind}${n > 1 ? ` ×${n}` : ''}${t ? `（${t.length > 100 ? t.slice(0, 100) + '…' : t}）` : ''}`,
        '',
        act,
      ].join('\n');
      mails.push({ subject: `即時通知：${w.reason}`, body });
    }
  }

  // 2a) watched CVEs with activity ON A HOST (detected / fix available / confirmed by distro advisory /
  //     resolved). One mail, grouped per host × CVE, each with the correct state and a link to that CVE.
  const watchState = (dk: string) =>
    dk.startsWith('watch-fixed') ? '解消' : dk.startsWith('watch-fixable') ? '対処可能（修正版あり）' : dk.startsWith('watch-distro') ? '影響あり（配布元勧告で確認）' : '検出';
  const onHost = toSend.filter((a) => a.kind === 'watch' && a.host_id);
  if (onHost.length) {
    const seen = new Set<string>();
    const byHost = new Map<string, { host_id: string; lines: string[]; hasFind: boolean }>();
    for (const a of onHost) {
      const host = hostOf(a); const cve = cveOf(a.title); const st = watchState(a.dedupe_key);
      const key = `${host}|${cve}|${st}`; if (seen.has(key)) continue; seen.add(key);
      const g = byHost.get(host) ?? { host_id: a.host_id as string, lines: [], hasFind: false };
      g.lines.push(`  ・${cve} ${st}　▶ ${url}/findings?host=${a.host_id}&q=${cve}&all=1`);
      if (st === '検出' || st.startsWith('影響あり')) g.hasFind = true;
      byHost.set(host, g);
    }
    const hosts = [...byHost.keys()];
    const anyFind = [...byHost.values()].some((g) => g.hasFind);
    const lines = [anyFind ? 'ウォッチ登録したCVEをホストで検出しました。' : 'ウォッチ登録したCVEに動きがありました（修正版の公開・解消など）。', ''];
    for (const [host, g] of byHost) { lines.push(`■ ${host}`); lines.push(...g.lines); }
    const subject = hosts.length === 1
      ? `即時通知：${hosts[0]} でウォッチ中CVE${anyFind ? 'を検出' : 'に動き'}`
      : `即時通知：ウォッチ中CVE${anyFind ? 'を検出' : 'に動き'}（${hosts[0]} ほか）`;
    mails.push({ subject, body: lines.join('\n') });
  }

  // 2b) watched CVEs with an UPSTREAM FIX published while affecting NO host (host_id is null). This is
  //     informational — not a detection — so it must not say "検出" or link to a (non-existent) host.
  const upstream = toSend.filter((a) => a.kind === 'watch' && !a.host_id);
  if (upstream.length) {
    const seen = new Set<string>();
    const lines = ['監視中のCVEに上流で修正版が公開されました（現在どのホストにも影響は検出されていません。対応は任意です）。', ''];
    for (const a of upstream) {
      const cve = cveOf(a.title); if (seen.has(cve)) continue; seen.add(cve);
      const fix = (a.title.match(/（([^（）]+)）/) ?? [])[1];
      lines.push(`・${cve}${fix ? `　修正版：${fix}` : ''}`);
      lines.push(`   ▶ 詳細 ${url}/cve/${cve}`);
    }
    const cves = [...seen];
    const subject = cves.length === 1
      ? `即時通知：ウォッチ中CVE ${cves[0]} に上流修正が公開`
      : `即時通知：ウォッチ中CVEに上流修正が公開（${cves[0]} ほか）`;
    mails.push({ subject, body: lines.join('\n') });
  }

  // 3) vulnerability "act now": one mail covering the KEV/緊急 findings on the hosts that just raised a
  //    vuln/kev alert. One line per CVE (collapsed across packages), each linking to that CVE on the host.
  if (vulnRows.length) {
    const byHost = new Map<string, { host_id: string; rows: VulnRow[] }>();
    for (const r of vulnRows) {
      const g = byHost.get(r.host) ?? { host_id: r.host_id, rows: [] };
      g.rows.push(r); byHost.set(r.host, g);
    }
    const hostGroups = [...byHost.entries()]
      .map(([host, g]) => ({ host, host_id: g.host_id, groups: groupByCve(g.rows).sort(cveSort) }))
      .sort((a, b) => Math.max(0, ...b.groups.map(cveScore)) - Math.max(0, ...a.groups.map(cveScore)));
    const actTotal = hostGroups.reduce((a, h) => a + h.groups.length, 0);
    const kevTotal = hostGroups.reduce((a, h) => a + h.groups.filter((g) => g.kev).length, 0);
    if (actTotal) {
      const PER_HOST = 8;
      const lines = [`対応すべき脆弱性を検出しました（${actTotal}件）。`, ''];
      for (const { host, host_id, groups } of hostGroups) {
        const kev = groups.filter((g) => g.kev).length, crit = groups.length - kev;
        lines.push(`■ ${host}　KEV ${kev}・緊急 ${crit}`);
        for (const g of groups.slice(0, PER_HOST)) {
          const pkgs = g.pkgs && g.pkgs.length ? (g.pkgs.length <= 1 ? g.pkgs[0] : `${g.pkgs[0]} ほか${g.pkgs.length - 1}`) : g.pkg;
          const cve = cveOf(g.vuln_id);
          const epss = g.epss != null ? ` EPSS ${Math.round(g.epss * 100)}%` : '';
          lines.push(`  ・${g.kev ? 'KEV' : '緊急'} ${cve}（${pkgs}）${epss}`);
          lines.push(`     ▶ ${url}/findings?host=${host_id}&q=${cve}&all=1`);
        }
        if (groups.length > PER_HOST) lines.push(`  …ほか ${groups.length - PER_HOST}件`);
      }
      const hostsList = hostGroups.map((h) => h.host);
      const subject = hostsList.length === 1
        ? `即時通知：${hostsList[0]} で${kevTotal ? 'KEV' : '緊急'}脆弱性を検出（${actTotal}件）`
        : `即時通知：脆弱性 ${actTotal}件を検出（${hostsList[0]} ほか）`;
      mails.push({ subject, body: lines.join('\n') });
    }
  }
  return mails;
}

// Send immediate notifications for newly-raised alerts. Urgent (intrusion/monitoring) events are one mail
// each; vulnerability "act now" findings and watched-CVE detections are one mail each. Non-immediate alerts
// are left for the daily digest.
export async function notifyPending(publicUrl: string): Promise<{ sent: number; skipped: number; error?: string }> {
  const pending = await q<PendingAlert>(
    "SELECT a.id, a.kind, a.severity, a.title, a.detail, a.created_at, a.host_id, (SELECT name FROM hosts WHERE id=a.host_id) AS host_name, a.dedupe_key FROM alerts a WHERE a.notified_at IS NULL ORDER BY a.created_at LIMIT 500",
  );
  if (!pending.length) return { sent: 0, skipped: 0 };
  const mail = await getMail();
  const policy = await getPolicy();
  const flags = await Promise.all(pending.map((a) => immediate(a, policy)));
  const toSend = pending.filter((_, i) => flags[i]);
  const skip = pending.filter((_, i) => !flags[i]);
  if (skip.length) await q("UPDATE alerts SET notified_at=now(), notify_error='digest only' WHERE id = ANY($1::bigint[])", [skip.map((a) => a.id)]);
  if (!toSend.length) return { sent: 0, skipped: skip.length };
  if (!mail.enabled) {
    await q("UPDATE alerts SET notified_at=now(), notify_error='mail disabled' WHERE id = ANY($1::bigint[])", [toSend.map((a) => a.id)]);
    return { sent: 0, skipped: pending.length };
  }

  // Fetch the "act now" vulnerability findings for the hosts that just raised a vuln/kev alert, then build.
  const vulnHosts = [...new Set(toSend.filter((a) => (a.kind === 'kev' || a.kind === 'vuln') && a.host_id).map((a) => a.host_id as string))];
  let vulnRows: VulnRow[] = [];
  if (vulnHosts.length) {
    const since = new Date(Date.now() - 24 * 3600_000);
    vulnRows = await q<VulnRow>(
      `SELECT f.host_id, h.name AS host, ${CVE_SELECT('$2')}
       FROM findings f JOIN hosts h ON h.id=f.host_id ${CVE_JOIN}
       WHERE f.status='open' AND f.host_id = ANY($1::uuid[]) AND (f.kev OR f.severity IN (${sevInSql(policy.mailLevel)}))`,
      [vulnHosts, since],
    );
  }
  const mails = buildImmediateMails(toSend, vulnRows, publicUrl);

  // Immediate-triggering alerts whose content is all below the mail line (e.g. a vuln alert whose findings
  // are all 高 or lower): nothing to send — just mark them handled.
  if (!mails.length) {
    await q("UPDATE alerts SET notified_at=now(), notify_error='緊急・KEVなし（メール対象外）' WHERE id = ANY($1::bigint[])", [toSend.map((a) => a.id)]);
    return { sent: 0, skipped: pending.length };
  }

  try {
    for (const m of mails) await sendMail(m.subject.slice(0, 200), m.body);
    await q('UPDATE alerts SET notified_at=now(), notify_error=NULL WHERE id = ANY($1::bigint[])', [toSend.map((a) => a.id)]);
    return { sent: toSend.length, skipped: skip.length };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await q('UPDATE alerts SET notify_error=$2 WHERE id = ANY($1::bigint[])', [toSend.map((a) => a.id), msg.slice(0, 500)]);
    return { sent: 0, skipped: skip.length, error: msg };
  }
}
