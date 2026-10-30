// Server-side file-integrity (AIDE-style) detection. The agent only reports path/hash/size/mtime
// read-only; the baseline lives here. Each report is diffed against the baseline, differences become
// change events (and alerts for security-sensitive paths), and the baseline is then auto-promoted.
// The first scan establishes the baseline quietly. A truncated (budget-limited) scan never deletes
// "missing" files, so a partial run cannot look like mass removal.
import { raiseAlert } from './alerts';
import { recordEvent } from './events';
import { q, q1, tx } from './db';
import type { FileHash } from './payload';

type Sev = 'critical' | 'high' | 'medium' | 'low';

// How much a change to this path matters for intrusion detection.
export function pathSeverity(p: string): Sev {
  if (/\/\.ssh\//.test(p) || /\/etc\/sudoers(\.d\/.*|)$/.test(p) || /\/etc\/(passwd|shadow|group|gshadow)$/.test(p) || /\/etc\/ssh\/sshd_config$/.test(p)) return 'critical';
  if (/^\/(bin|sbin|usr\/bin|usr\/sbin|usr\/local\/bin|usr\/local\/sbin)\//.test(p) || /\/etc\/(cron|crontab)/.test(p) || /\/etc\/systemd\/system\//.test(p) || /^\/boot\//.test(p)) return 'high';
  if (/^\/etc\//.test(p)) return 'medium';
  return 'low';
}

const nul = (x: string) => x.replace(/\u0000/g, '');
const SEV_LABEL: Record<Sev, string> = { critical: '重大', high: '高', medium: '中', low: '低' };

interface Change { path: string; kind: 'added' | 'changed' | 'removed'; sev: Sev }

export async function ingestFiles(
  host: { id: string; name: string; baseline_done: boolean },
  files: FileHash[] | null | undefined,
  truncated: boolean,
): Promise<void> {
  if (!Array.isArray(files)) return; // not collected this run

  const base = new Map(
    (await q<{ path: string; sha: string }>('SELECT path, sha FROM host_file_baseline WHERE host_id=$1', [host.id])).map((r) => [r.path, r.sha]),
  );
  const firstBaseline = base.size === 0;
  // Until a non-truncated scan has arrived the baseline is still converging: a file "first seen" is
  // a pre-existing file the earlier (budget-limited) scan had not reached, not a real addition.
  const complete = !firstBaseline && !!(await q1<{ c: boolean }>('SELECT file_baseline_complete AS c FROM hosts WHERE id=$1', [host.id]))?.c;

  const reported = new Map<string, FileHash>();
  for (const f of files) {
    const p = nul(String(f.p ?? '')).slice(0, 1024);
    if (p) reported.set(p, { p, h: nul(String(f.h ?? '')).slice(0, 128), s: Number(f.s) || 0, m: Number(f.m) || 0 });
  }

  const changes: Change[] = [];
  if (!firstBaseline) {
    for (const [p, f] of reported) {
      const prev = base.get(p);
      if (prev === undefined) { if (complete) changes.push({ path: p, kind: 'added', sev: pathSeverity(p) }); } // else: converging, absorb quietly
      else if (prev !== f.h) changes.push({ path: p, kind: 'changed', sev: pathSeverity(p) });
    }
    if (!truncated) {
      for (const p of base.keys()) if (!reported.has(p)) changes.push({ path: p, kind: 'removed', sev: pathSeverity(p) });
    }
  }

  // Auto-promote the baseline to the newly reported state.
  await tx(async (c) => {
    const rows = [...reported.values()];
    for (let i = 0; i < rows.length; i += 2000) {
      const ch = rows.slice(i, i + 2000);
      await c.query(
        `INSERT INTO host_file_baseline(host_id, path, sha, size, mtime)
         SELECT $1, * FROM unnest($2::text[], $3::text[], $4::bigint[], $5::bigint[])
         ON CONFLICT (host_id, path) DO UPDATE SET sha=EXCLUDED.sha, size=EXCLUDED.size, mtime=EXCLUDED.mtime`,
        [host.id, ch.map((x) => x.p), ch.map((x) => x.h), ch.map((x) => x.s), ch.map((x) => x.m)],
      );
    }
    if (!truncated) {
      const removed = [...base.keys()].filter((p) => !reported.has(p));
      for (let i = 0; i < removed.length; i += 5000) {
        await c.query('DELETE FROM host_file_baseline WHERE host_id=$1 AND path = ANY($2::text[])', [host.id, removed.slice(i, i + 5000)]);
      }
    }
    if (firstBaseline) await c.query('UPDATE hosts SET file_baseline_at=now() WHERE id=$1', [host.id]);
    // a non-truncated scan means every configured path was reached: the baseline is now complete
    if (!truncated) await c.query('UPDATE hosts SET file_baseline_complete=true WHERE id=$1 AND NOT file_baseline_complete', [host.id]);
  });

  if (firstBaseline) {
    await recordEvent({ hostId: host.id, kind: 'host_state', important: false, count: reported.size,
      title: `${host.name}：ファイル改ざん検知のベースラインを確定（${reported.size}ファイル${truncated ? '・収集中' : ''}）` });
    return;
  }

  // Persistent truncation = a real coverage gap (files never scanned), not just slow convergence.
  if (truncated) {
    const old = await q1<{ old: boolean }>("SELECT file_baseline_at < now() - interval '6 hours' AS old FROM hosts WHERE id=$1", [host.id]);
    if (old?.old) {
      await raiseAlert({
        kind: 'agent', severity: 'high', hostId: host.id,
        title: `[${host.name}] ファイル改ざん検知のスキャンが打ち切られ続けています（一部が監視対象外）`,
        detail: '監視対象ディレクトリが大きすぎてスキャンが上限に達しています。大きなデータ/ログのディレクトリを監視対象から外す（除外設定）か、監視パスを絞ってください。このままでは打ち切られた範囲の改ざんを検知できません。',
        dedupeKey: `file-coverage:${host.id}:${new Date().toISOString().slice(0, 10)}`,
      });
    }
  }
  if (!changes.length) return;

  const KIND: Record<Change['kind'], string> = { added: '追加', changed: '変更', removed: '削除' };
  const rank: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  changes.sort((a, b) => rank[a.sev] - rank[b.sev]);
  const notable = changes.filter((c) => c.sev === 'critical' || c.sev === 'high');

  // One change-event summarising the run (important if anything sensitive moved).
  const byKind = { added: 0, changed: 0, removed: 0 };
  for (const c of changes) byKind[c.kind]++;
  await recordEvent({
    hostId: host.id, kind: 'host_state', important: notable.length > 0, count: changes.length,
    title: `${host.name}：監視ファイルの変化 ${changes.length}件（追加${byKind.added}・変更${byKind.changed}・削除${byKind.removed}${notable.length ? `、重要 ${notable.length}` : ''}）`,
  });

  if (!host.baseline_done) return; // still establishing the host baseline: no per-change alerts

  // Alert on security-sensitive changes only (critical + high), individually up to a cap.
  const CAP = 25;
  for (const c of notable.slice(0, CAP)) {
    await raiseAlert({
      kind: 'state',
      severity: c.sev,
      hostId: host.id,
      title: `[${host.name}] 監視ファイルの${KIND[c.kind]}（${SEV_LABEL[c.sev]}）：${c.path}`,
      detail: 'AIDE相当のファイル整合性チェックで検出しました。意図した変更でなければ侵害を疑ってください。',
      dedupeKey: `file:${host.id}:${c.kind}:${c.path}`,
    });
  }
  if (notable.length > CAP) {
    await raiseAlert({
      kind: 'state', severity: 'high', hostId: host.id,
      title: `[${host.name}] 監視ファイルの重要な変化が ${notable.length}件（先頭${CAP}件を個別通知）`,
      detail: notable.slice(CAP, CAP + 50).map((c) => `${KIND[c.kind]}: ${c.path}`).join('\n'),
      dedupeKey: `file-bulk:${host.id}:${Date.now()}`,
    });
  }
}
