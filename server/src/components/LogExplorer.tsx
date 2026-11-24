'use client';

import { useEffect, useRef, useState } from 'react';
import type { EChartsType } from 'echarts';
import { useMask } from '@/components/Mask';
import { pseudo } from '@/lib/mask';
import { CAT_LABEL } from '@/lib/logcat';
import { applyLogFilter, readLogFilter, type LogFilter } from '@/lib/logfilter';
import { MEASURES, DIM_LABEL, CHARTS, PRESETS, AGG_FILTER_KEYS, type MeasureKey, type DimKey, type ChartKey } from '@/lib/logexplore';

interface AggRow { k: string; d: string; v: number }
interface AggResp { days: string[]; rows: AggRow[] }
const PAL = ['#0e7c86', '#2563eb', '#8b5cf6', '#d97706', '#db2777', '#0ea5e9', '#65a30d', '#dc2626', '#059669', '#7c3aed'];
const TOP = 8;

export function LogExplorer({ hosts, ruleTitles }: { hosts: Record<string, string>; ruleTitles: Record<string, string> }) {
  const masked = useMask();
  const [measure, setMeasure] = useState<MeasureKey>('logs');
  const [dim, setDim] = useState<DimKey>('host');
  const [chart, setChart] = useState<ChartKey>('stack');
  const [range, setRange] = useState('30');
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [data, setData] = useState<AggResp>({ days: [], rows: [] });
  const [loading, setLoading] = useState(false);
  const [ready, setReady] = useState(0);
  const elRef = useRef<HTMLDivElement>(null);
  const chRef = useRef<EChartsType | null>(null);
  const reqId = useRef(0);
  const clickRef = useRef<(p: { seriesIndex?: number; dataIndex?: number; name?: string; value?: unknown }) => void>(() => {});

  const md = MEASURES.find((m) => m.k === measure)!;
  const unit = md.unit;

  // init echarts once (client only). The click handler is dispatched through a ref so it always sees the
  // latest state instead of the closure captured at init time.
  useEffect(() => {
    let disposed = false;
    if (!elRef.current) return;
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    import('echarts').then((ec) => {
      if (disposed || !elRef.current) return;
      const inst = ec.init(elRef.current, dark ? 'dark' : undefined, { renderer: 'canvas' });
      inst.on('click', (p: unknown) => clickRef.current(p as { seriesIndex?: number; dataIndex?: number; name?: string; value?: unknown }));
      chRef.current = inst;
      setReady((r) => r + 1);
    });
    const onResize = () => chRef.current?.resize();
    window.addEventListener('resize', onResize);
    return () => { disposed = true; window.removeEventListener('resize', onResize); chRef.current?.dispose(); chRef.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // seed filters from the URL once (deep-link friendly)
  useEffect(() => { const f = readLogFilter(); const seed: Record<string, string> = {};
    for (const k of AGG_FILTER_KEYS) if (f[k as keyof LogFilter]) seed[k] = f[k as keyof LogFilter]!;
    if (Object.keys(seed).length) setFilters(seed);
  }, []);

  // when the measure changes, keep only still-valid dim + filters common to any table (host/day)
  useEffect(() => {
    if (!md.dims.includes(dim)) setDim(md.dims[0]);
    setFilters((prev) => { const keep: Record<string, string> = {}; for (const k of ['host', 'day']) if (prev[k]) keep[k] = prev[k]; return keep; });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [measure]);

  // fetch aggregate
  useEffect(() => {
    const id = ++reqId.current; setLoading(true);
    const u = new URLSearchParams({ measure, dim, range });
    for (const [k, v] of Object.entries(filters)) if (v) u.set(k, v);
    fetch('/api/logs/agg?' + u.toString()).then((r) => r.ok ? r.json() : { days: [], rows: [] })
      .then((d: AggResp) => { if (id === reqId.current) setData(d); })
      .catch(() => { if (id === reqId.current) setData({ days: [], rows: [] }); })
      .finally(() => { if (id === reqId.current) setLoading(false); });
  }, [measure, dim, range, filters]);

  // ---- label / mask ----
  const label = (k: string): string => {
    if (dim === 'host') return masked ? pseudo('host', k) : (hosts[k] ?? k);
    if (dim === 'vhost') return masked ? pseudo('domain', k) : k;
    if (dim === 'cat') return CAT_LABEL[k] ?? k;
    if (dim === 'rule') return ruleTitles[k] ?? k;
    return k;
  };
  const md2 = (d: string) => { const p = d.split('-'); return `${Number(p[1])}/${Number(p[2])}`; };
  const fmt = (v: number) => unit === 'bytes'
    ? (v >= 1e9 ? (v / 1e9).toFixed(1) + 'GB' : v >= 1e6 ? (v / 1e6).toFixed(1) + 'MB' : v >= 1e3 ? Math.round(v / 1e3) + 'KB' : v + 'B')
    : (v >= 1e6 ? (v / 1e6).toFixed(1) + 'M' : v >= 1e3 ? (v / 1e3).toFixed(1) + 'k' : String(v));

  // keep parallel rawKey arrays so a click maps a (masked) label back to the real key
  const keyArrays = useRef<{ series: string[]; cat: string[]; ydays: string[] }>({ series: [], cat: [], ydays: [] });

  function drill(rawK: string, day?: string) {
    if (!rawK || rawK === '(なし)') return;
    const isStatus = dim === 'status';
    const aggPatch: Record<string, string> = {};
    if (!isStatus && (AGG_FILTER_KEYS as string[]).includes(dim)) aggPatch[dim] = rawK;
    if (day) aggPatch.day = day;
    const next = { ...filters, ...aggPatch };
    setFilters(next);
    const rawPatch: LogFilter = { ...aggPatch };
    if (isStatus) rawPatch.status = rawK;
    applyLogFilter(rawPatch, { scroll: true });
  }

  function onChartClick(p: { seriesIndex?: number; dataIndex?: number; name?: string; value?: unknown }) {
    const ka = keyArrays.current;
    if (chart === 'line' || chart === 'area' || chart === 'stack') {
      const k = p.seriesIndex != null ? ka.series[p.seriesIndex] : undefined;
      const day = data.days[p.dataIndex ?? -1];
      if (k) drill(k, day);
    } else if (chart === 'bar' || chart === 'pie') {
      const k = p.dataIndex != null ? ka.cat[p.dataIndex] : undefined;
      if (k) drill(k);
    } else if (chart === 'heat') {
      const arr = p.value as number[] | undefined;
      if (arr) { const k = ka.cat[arr[1]]; const day = ka.ydays[arr[0]]; if (k) drill(k, day); }
    }
  }
  clickRef.current = onChartClick;

  // build + set option whenever data / chart / theme ready
  useEffect(() => {
    const ch = chRef.current; if (!ch) return;
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    const tc = dark ? '#e7eef5' : '#15202b';
    const ax = { axisLine: { lineStyle: { color: dark ? '#243445' : '#dce4ec' } }, axisLabel: { color: dark ? '#93a3b4' : '#5d6b7a', fontSize: 10 }, splitLine: { lineStyle: { color: dark ? '#1b2936' : '#eef2f6' } } };
    const days = data.days;
    // totals per key
    const totals = new Map<string, number>();
    for (const r of data.rows) totals.set(r.k, (totals.get(r.k) ?? 0) + r.v);
    const topKeys = [...totals.entries()].sort((a, b) => b[1] - a[1]).slice(0, TOP).map((e) => e[0]);
    const ka = keyArrays.current;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let opt: any = { backgroundColor: 'transparent', color: PAL, textStyle: { color: tc, fontFamily: 'Noto Sans JP' }, legend: { top: 0, type: 'scroll', textStyle: { color: tc, fontSize: 11 } }, grid: { left: 48, right: 14, top: 28, bottom: 46 } };

    if (chart === 'line' || chart === 'area' || chart === 'stack') {
      ka.series = topKeys;
      const byK: Record<string, Record<string, number>> = {};
      for (const k of topKeys) byK[k] = {};
      for (const r of data.rows) if (byK[r.k]) byK[r.k][r.d] = (byK[r.k][r.d] ?? 0) + r.v;
      opt.tooltip = { trigger: 'axis' };
      opt.xAxis = { type: 'category', data: days.map(md2), ...ax };
      opt.yAxis = { type: 'value', ...ax, axisLabel: { formatter: fmt, color: ax.axisLabel.color, fontSize: 10 } };
      opt.dataZoom = [{ type: 'inside' }, { type: 'slider', height: 14, bottom: 14 }];
      opt.legend.data = topKeys.map(label);
      opt.series = topKeys.map((k) => ({ name: label(k), type: chart === 'stack' ? 'bar' : 'line', stack: chart === 'stack' ? 't' : undefined, areaStyle: chart === 'area' ? { opacity: 0.25 } : undefined, smooth: chart !== 'stack', emphasis: { focus: 'series' }, data: days.map((d) => byK[k][d] ?? 0) }));
    } else if (chart === 'bar') {
      ka.cat = topKeys;
      opt.legend = { show: false };
      opt.tooltip = { trigger: 'item' };
      opt.xAxis = { type: 'category', data: topKeys.map(label), axisLabel: { color: tc, fontSize: 10, interval: 0, rotate: topKeys.length > 6 ? 30 : 0 }, ...{ axisLine: ax.axisLine } };
      opt.yAxis = { type: 'value', ...ax, axisLabel: { formatter: fmt, color: ax.axisLabel.color, fontSize: 10 } };
      opt.series = [{ type: 'bar', barMaxWidth: 34, data: topKeys.map((k, i) => ({ value: totals.get(k) ?? 0, itemStyle: { color: PAL[i % PAL.length] } })) }];
    } else if (chart === 'pie') {
      ka.cat = topKeys;
      opt.grid = undefined;
      opt.tooltip = { trigger: 'item', formatter: (pp: { name: string; value: number; percent: number }) => `${pp.name}: ${fmt(pp.value)} (${pp.percent}%)` };
      opt.legend = { type: 'scroll', orient: 'horizontal', bottom: 0, textStyle: { color: tc, fontSize: 11 }, data: topKeys.map(label) };
      opt.series = [{ type: 'pie', radius: ['40%', '68%'], center: ['50%', '46%'], data: topKeys.map((k) => ({ name: label(k), value: totals.get(k) ?? 0 })), label: { color: tc, fontSize: 11 } }];
    } else if (chart === 'heat') {
      ka.cat = topKeys; ka.ydays = days;
      const cell = new Map<string, number>(); let max = 1;
      for (const r of data.rows) if (totals.has(r.k) && topKeys.includes(r.k)) { const key = r.k + '|' + r.d; const v = (cell.get(key) ?? 0) + r.v; cell.set(key, v); if (v > max) max = v; }
      const hd: number[][] = [];
      topKeys.forEach((k, yi) => days.forEach((d, xi) => hd.push([xi, yi, cell.get(k + '|' + d) ?? 0])));
      opt.grid = { left: 96, right: 14, top: 10, bottom: 54 };
      opt.legend = { show: false };
      opt.tooltip = { position: 'top', formatter: (pp: { value: number[] }) => `${label(topKeys[pp.value[1]])} ${md2(days[pp.value[0]])}: ${fmt(pp.value[2])}` };
      opt.xAxis = { type: 'category', data: days.map(md2), ...ax };
      opt.yAxis = { type: 'category', data: topKeys.map(label), ...ax };
      opt.visualMap = { min: 0, max, calculable: true, orient: 'horizontal', left: 'center', bottom: 4, itemHeight: 70, textStyle: { color: tc }, inRange: { color: dark ? ['#15202b', '#2dd4bf', '#f6c343', '#e8743b'] : ['#eef2f6', '#8fcbd0', '#f6c343', '#e8743b'] } };
      opt.series = [{ type: 'heatmap', data: hd, emphasis: { itemStyle: { borderColor: dark ? '#fff' : '#000', borderWidth: 1 } } }];
    } else { ch.clear(); return; } // table rendered in JSX

    ch.clear();
    ch.resize();
    ch.setOption(opt, true);
  }, [data, chart, ready, masked]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---- table data ----
  const totalsForTable = (() => { const t = new Map<string, number>(); for (const r of data.rows) t.set(r.k, (t.get(r.k) ?? 0) + r.v); return [...t.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40); })();
  const grand = totalsForTable.reduce((a, e) => a + e[1], 0) || 1;

  const condKeys = Object.keys(filters).filter((k) => filters[k]);
  const removeFilter = (k: string) => { const n = { ...filters }; delete n[k]; setFilters(n); applyLogFilter({ [k]: '' } as LogFilter, { scroll: false }); };
  const chipLabel = (k: string) => k === 'host' ? `ホスト：${masked ? pseudo('host', filters[k]) : (hosts[filters[k]] ?? filters[k])}` : k === 'cat' ? `カテゴリ：${CAT_LABEL[filters[k]] ?? filters[k]}` : k === 'rule' ? `ルール：${ruleTitles[filters[k]] ?? filters[k]}` : `${DIM_LABEL[k as DimKey] ?? k}：${filters[k]}`;

  return (
    <div>
      {/* presets */}
      <div className="mb-3 flex flex-wrap gap-1.5">
        {PRESETS.map((p) => (
          <button key={p.label} type="button" onClick={() => { setMeasure(p.measure); setDim(p.dim); setChart(p.chart); setFilters({}); }}
            className="rounded-full border border-line bg-bg px-2.5 py-1 text-xs hover:border-accent">{p.label}</button>
        ))}
      </div>

      {/* controls */}
      <div className="mb-3 flex flex-wrap items-end gap-2 text-sm">
        <label className="flex flex-col gap-0.5"><span className="text-[11px] text-muted">指標</span>
          <select value={measure} onChange={(e) => setMeasure(e.target.value as MeasureKey)} className="input sm:w-auto">{MEASURES.map((m) => <option key={m.k} value={m.k}>{m.label}</option>)}</select></label>
        <label className="flex flex-col gap-0.5"><span className="text-[11px] text-muted">分割軸</span>
          <select value={dim} onChange={(e) => setDim(e.target.value as DimKey)} className="input sm:w-auto">{md.dims.map((d) => <option key={d} value={d}>{DIM_LABEL[d]}</option>)}</select></label>
        <label className="flex flex-col gap-0.5"><span className="text-[11px] text-muted">グラフ</span>
          <select value={chart} onChange={(e) => setChart(e.target.value as ChartKey)} className="input sm:w-auto">{CHARTS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
        <label className="flex flex-col gap-0.5"><span className="text-[11px] text-muted">期間</span>
          <select value={range} onChange={(e) => setRange(e.target.value)} className="input sm:w-auto">{[['7', '7日'], ['30', '30日'], ['90', '90日']].map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></label>
        {loading && <span className="text-xs text-muted">読み込み中…</span>}
      </div>

      {/* filter chips */}
      <div className="mb-2 flex min-h-[1.6rem] flex-wrap items-center gap-2">
        {condKeys.length === 0 ? <span className="text-xs text-muted">条件なし（全体）。棒・凡例・セル・行をクリックすると、その値で絞り込み（ドリル）します。</span> : (
          <>{condKeys.map((k) => (
            <button key={k} type="button" onClick={() => removeFilter(k)} className="inline-flex items-center gap-1 rounded-full border border-line px-2 py-0.5 text-xs" style={{ background: 'var(--soft)' }}>{chipLabel(k)}<span className="text-muted">✕</span></button>
          ))}
            <button type="button" onClick={() => { setFilters({}); applyLogFilter(Object.fromEntries(condKeys.map((k) => [k, ''])) as LogFilter, { scroll: false }); }} className="text-xs text-accent">すべて解除</button>
          </>
        )}
      </div>

      {/* chart (always mounted so the ECharts instance keeps its DOM) + table overlay */}
      <div className={chart === 'table' ? 'hidden' : 'relative'}>
        <div ref={elRef} style={{ width: '100%', height: 340 }} />
        {data.rows.length === 0 && !loading && chart !== 'table' && (
          <div className="absolute inset-0 flex items-center justify-center text-sm text-muted">この条件に該当するデータがありません。</div>
        )}
      </div>
      {chart === 'table' && (
        <div className="max-h-[360px] overflow-auto">
          <table className="tbl"><thead><tr><th>{DIM_LABEL[dim]}</th><th className="text-right">{md.label}</th><th className="text-right">%</th></tr></thead>
            <tbody>{totalsForTable.length === 0 ? <tr><td colSpan={3} className="text-sm text-muted">データがありません。</td></tr> : totalsForTable.map(([k, v], i) => (
              <tr key={k} onClick={() => drill(k)} className="cursor-pointer hover:bg-[var(--soft)]">
                <td><span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: PAL[i % PAL.length] }} />{label(k)}</span></td>
                <td className="text-right font-mono">{fmt(v)}</td><td className="text-right text-muted">{(v / grand * 100).toFixed(1)}</td>
              </tr>))}</tbody></table>
        </div>
      )}
      <p className="mt-2 text-xs text-muted">概要 → 分割軸でブレイクダウン → クリックでドリル → 下の<b>生ログ</b>へ（同じ条件が反映されます）。</p>
    </div>
  );
}
