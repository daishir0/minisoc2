// Shared WHERE builder for the findings list, so the page and the CSV export apply identical filters
// (status / severity view / host / KEV / source / system / free-text). Single source of truth: if the
// filtering rules change, both the on-screen table and the downloaded CSV change together.
import { getPolicy } from './settings';
import { sevInSql } from './severity';

export const SEV_VALUES = ['critical', 'high', 'medium', 'low', 'unknown'];

export interface FindingsFilter {
  status: string;
  whereSql: string;
  params: unknown[];
  showAll: boolean;
  sevParam: string;
  screenLevel: string;
}

export async function buildFindingsWhere(sp: Record<string, string | undefined>): Promise<FindingsFilter> {
  const status = ['open', 'suppressed', 'resolved'].includes(sp.status ?? '') ? sp.status! : 'open';
  const where = ['f.status=$1'];
  const params: unknown[] = [status];
  // The severity dropdown carries the active view so it can never disagree with the results:
  //   __act__ (default) = KEV・対応ライン only, __all__ = every severity, or a specific severity.
  const sevParam = SEV_VALUES.includes(sp.severity ?? '') ? sp.severity! : '';
  const showAll = sp.all === '1' || sp.severity === '__all__' || !!sevParam;
  const screenLevel = (await getPolicy()).screenLevel;
  if (sevParam) { params.push(sevParam); where.push(`f.severity=$${params.length}`); }
  else if (!showAll && sp.kev !== '1') where.push(`(f.kev OR f.severity IN (${sevInSql(screenLevel)}))`);
  if (sp.host && /^[0-9a-f-]{36}$/.test(sp.host)) { params.push(sp.host); where.push(`f.host_id=$${params.length}`); }
  if (sp.kev === '1') where.push('f.kev');
  if (sp.source) { params.push(sp.source); where.push(`f.source=$${params.length}`); }
  if (sp.system) { params.push(sp.system); where.push(`$${params.length} = ANY(f.systems)`); }
  if (sp.q) { params.push(`%${sp.q}%`); where.push(`(f.vuln_id ILIKE $${params.length} OR f.pkg ILIKE $${params.length})`); }
  return { status, whereSql: where.join(' AND '), params, showAll, sevParam, screenLevel };
}
