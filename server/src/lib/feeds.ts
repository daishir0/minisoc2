import { q, tx } from './db';
import { recordEvent } from './events';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export async function markFeed(name: string, ok: boolean, info: { count?: number; error?: string } = {}): Promise<void> {
  if (ok) {
    await q(
      `INSERT INTO feed_status(name, last_success, item_count) VALUES ($1, now(), $2)
       ON CONFLICT (name) DO UPDATE SET last_success=now(), item_count=COALESCE(EXCLUDED.item_count, feed_status.item_count)`,
      [name, info.count ?? null],
    );
  } else {
    await q(
      `INSERT INTO feed_status(name, last_error, last_error_at) VALUES ($1, $2, now())
       ON CONFLICT (name) DO UPDATE SET last_error=EXCLUDED.last_error, last_error_at=now()`,
      [name, (info.error ?? '').slice(0, 1000)],
    );
  }
}

interface KevItem {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

export async function syncKev(): Promise<number> {
  try {
    const res = await fetch(KEV_URL, { headers: { 'user-agent': 'minisoc2' } });
    if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
    const j = (await res.json()) as { vulnerabilities: KevItem[] };
    const items = j.vulnerabilities ?? [];
    // An empty or tiny catalog means a broken download, not a real change: keep the old data.
    if (items.length < 500) throw new Error(`KEV catalog suspiciously small (${items.length})`);
    const before = new Set((await q<{ cve: string }>('SELECT cve FROM kev')).map((r) => r.cve));
    const added = before.size ? items.filter((x) => !before.has(x.cveID)).map((x) => x.cveID) : [];
    await tx(async (c) => {
      await c.query('DELETE FROM kev');
      for (let i = 0; i < items.length; i += 1000) {
        const ch = items.slice(i, i + 1000);
        await c.query(
          `INSERT INTO kev(cve, vendor, product, name, date_added, due_date, ransomware)
           SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::date[], $6::date[], $7::text[]) ON CONFLICT DO NOTHING`,
          [ch.map((x) => x.cveID), ch.map((x) => x.vendorProject), ch.map((x) => x.product), ch.map((x) => x.vulnerabilityName),
            ch.map((x) => x.dateAdded), ch.map((x) => x.dueDate || null), ch.map((x) => x.knownRansomwareCampaignUse ?? null)],
        );
      }
    });
    await markFeed('kev', true, { count: items.length });
    if (added.length) {
      const ours = await q<{ n: string }>('SELECT count(DISTINCT vuln_id) AS n FROM findings WHERE status=\'open\' AND vuln_id = ANY($1)', [added]);
      const n = Number(ours[0]?.n ?? 0);
      await recordEvent({ kind: 'feed', important: n > 0, count: added.length, title: `CISA KEV に ${added.length}件追加（うち当環境に関係あり ${n}件）`, detail: added.slice(0, 20).join(' ') });
    }
    return items.length;
  } catch (e) {
    await markFeed('kev', false, { error: e instanceof Error ? e.message : String(e) });
    throw e;
  }
}
