// Shared constants for the log explorer (one BI panel over the collected logs). Pure data, importable by
// both the aggregation API (server) and the LogExplorer component (client). A measure declares its base
// table (server-side, see logagg.ts) and which dimensions it can be sliced by. A "mode" turns the same
// measure into an anomaly view: total (as-is), ratio (当日 ÷ 直近7日平均＝平常比), wow (今週 ÷ 前週＝前週比).

export type MeasureKey = 'logs' | 'web' | 's4' | 's5' | 'bytes' | 'rule' | 'failed' | 'ips' | 'ipreq';
export type DimKey = 'host' | 'cat' | 'source' | 'vhost' | 'status' | 'rule' | 'ip' | 'day';
export type ChartKey = 'stack' | 'line' | 'area' | 'bar' | 'pie' | 'heat' | 'table';
export type ModeKey = 'total' | 'ratio' | 'wow';

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
  { k: 'ipreq', label: 'Webリクエスト(IP別)', unit: 'count', dims: ['host', 'vhost', 'ip', 'day'] },
];

export const DIM_LABEL: Record<DimKey, string> = {
  host: 'ホスト', cat: 'カテゴリ', source: 'ソース', vhost: 'vhost', status: 'ステータス', rule: '検知ルール', ip: 'IP', day: '日',
};

export const CHARTS: [ChartKey, string][] = [
  ['stack', '積み上げ棒'], ['line', '折れ線'], ['area', 'エリア'], ['bar', '棒(ランキング)'], ['pie', '円(構成比)'], ['heat', 'ヒートマップ'], ['table', '表'],
];
// In an anomaly mode the value is a single ratio per dimension value, so only ranking/table apply.
export const DEV_CHARTS: [ChartKey, string][] = [['bar', '棒(ランキング)'], ['table', '表']];

// Filters the aggregation chart can honour.
export const AGG_FILTER_KEYS: DimKey[] = ['host', 'cat', 'vhost', 'rule', 'source', 'ip', 'day'];

export interface Preset { label: string; measure: MeasureKey; dim: DimKey; chart: ChartKey; mode: ModeKey; filters?: Record<string, string> }
export const PRESETS: Preset[] = [
  // A. 今日の異常（まず見る）
  { label: 'いつもと違うログ量(平常比)', measure: 'logs', dim: 'host', chart: 'bar', mode: 'ratio' },
  { label: 'Web 5xx 急増(平常比)', measure: 's5', dim: 'vhost', chart: 'bar', mode: 'ratio' },
  { label: 'Web 4xx 急増(平常比)', measure: 's4', dim: 'vhost', chart: 'bar', mode: 'ratio' },
  { label: 'サイトの沈黙/急増', measure: 'web', dim: 'vhost', chart: 'line', mode: 'total' },
  // B. 認証・侵入
  { label: 'SSH失敗の集中(日×host)', measure: 'failed', dim: 'host', chart: 'heat', mode: 'total' },
  { label: '初見IPのログイン成功', measure: 'rule', dim: 'host', chart: 'bar', mode: 'total', filters: { rule: 'ssh_accept_new_ip' } },
  { label: 'sudo異常', measure: 'rule', dim: 'host', chart: 'bar', mode: 'total', filters: { rule: 'sudo_new_user' } },
  // C. Web挙動
  { label: '単一IPの集中', measure: 'ipreq', dim: 'ip', chart: 'bar', mode: 'total' },
  { label: 'ステータス構成の変化', measure: 'web', dim: 'status', chart: 'stack', mode: 'total' },
  // D. 全体俯瞰
  { label: 'ホスト×日 ヒートマップ', measure: 'logs', dim: 'host', chart: 'heat', mode: 'total' },
  { label: '検知ルールの増減(前週比)', measure: 'rule', dim: 'rule', chart: 'bar', mode: 'wow' },
];
