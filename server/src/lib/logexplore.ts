// Shared constants for the log explorer (one BI panel over the collected logs). Pure data, importable by
// both the aggregation API (server) and the LogExplorer component (client). A measure declares which base
// table it comes from (server-side, see logagg.ts) and which dimensions it can be sliced by.

export type MeasureKey = 'logs' | 'web' | 's4' | 's5' | 'bytes' | 'rule' | 'failed' | 'ips';
export type DimKey = 'host' | 'cat' | 'source' | 'vhost' | 'status' | 'rule' | 'day';
export type ChartKey = 'stack' | 'line' | 'area' | 'bar' | 'pie' | 'heat' | 'table';

export interface MeasureDef { k: MeasureKey; label: string; unit: 'count' | 'bytes'; dims: DimKey[] }

export const MEASURES: MeasureDef[] = [
  { k: 'logs', label: 'ログ量（行）', unit: 'count', dims: ['host', 'cat', 'source', 'day'] },
  { k: 'web', label: 'Webリクエスト', unit: 'count', dims: ['host', 'vhost', 'status', 'day'] },
  { k: 's4', label: '4xxエラー', unit: 'count', dims: ['host', 'vhost', 'day'] },
  { k: 's5', label: '5xxエラー', unit: 'count', dims: ['host', 'vhost', 'day'] },
  { k: 'bytes', label: '転送量(Web)', unit: 'bytes', dims: ['host', 'vhost', 'day'] },
  { k: 'rule', label: '検知ルール数', unit: 'count', dims: ['host', 'rule', 'day'] },
  { k: 'failed', label: 'ログイン失敗', unit: 'count', dims: ['host', 'day'] },
  { k: 'ips', label: '一意IP数(Web)', unit: 'count', dims: ['host', 'vhost', 'day'] },
];

export const DIM_LABEL: Record<DimKey, string> = {
  host: 'ホスト', cat: 'カテゴリ', source: 'ソース', vhost: 'vhost', status: 'ステータス', rule: '検知ルール', day: '日',
};

export const CHARTS: [ChartKey, string][] = [
  ['stack', '積み上げ棒'], ['line', '折れ線'], ['area', 'エリア'], ['bar', '棒(ランキング)'], ['pie', '円(構成比)'], ['heat', 'ヒートマップ'], ['table', '表'],
];

// Filters the aggregation chart can honour (status/source go to raw logs only where a measure can't group by
// them). day is handled via the range picker + drill.
export const AGG_FILTER_KEYS: DimKey[] = ['host', 'cat', 'vhost', 'rule', 'source', 'day'];

export interface Preset { label: string; measure: MeasureKey; dim: DimKey; chart: ChartKey }
export const PRESETS: Preset[] = [
  { label: 'ホスト別ログ量', measure: 'logs', dim: 'host', chart: 'stack' },
  { label: 'カテゴリ別の推移', measure: 'logs', dim: 'cat', chart: 'area' },
  { label: 'Webステータス構成', measure: 'web', dim: 'status', chart: 'pie' },
  { label: '検知ルール ランキング', measure: 'rule', dim: 'rule', chart: 'bar' },
  { label: 'ログイン失敗が多いホスト', measure: 'failed', dim: 'host', chart: 'bar' },
  { label: 'ホスト×日 ヒートマップ', measure: 'logs', dim: 'host', chart: 'heat' },
  { label: 'vhost別 5xx 推移', measure: 's5', dim: 'vhost', chart: 'line' },
];
