// Priority bucketing — "which do I do first", per the SSVC-style idea of turning a long list into a
// short Act/Attend/Track triage. Inputs are the signals we already have plus EPSS (exploit probability).
// Kept dependency-free and generic so the same rule drives the list, the home page and notifications.
export type Bucket = 'act' | 'attend' | 'track';

export const BUCKET_LABEL: Record<Bucket, string> = { act: '今すぐ', attend: '今週', track: '様子見' };
export const BUCKET_ORDER: Record<Bucket, number> = { act: 0, attend: 1, track: 2 };

export interface RiskInput {
  kev: boolean;            // CISA KEV = known exploited → always Act
  epss: number | null;     // 0..1, null if unknown
  exposure: string;        // 'public' raises urgency
  severity: string;        // critical/high/...
}

// Thresholds are deliberately simple and explainable. KEV dominates; then exploit probability (EPSS),
// weighted up for internet-exposed systems; severity is the fallback when EPSS is unknown.
export function riskBucket(x: RiskInput): Bucket {
  if (x.kev) return 'act';
  const pub = x.exposure === 'public';
  const e = x.epss ?? 0;
  if (e >= 0.5) return 'act';
  if (pub && (e >= 0.1 || x.severity === 'critical')) return 'act';
  if (e >= 0.1 || x.severity === 'critical' || x.severity === 'high') return 'attend';
  return 'track';
}

// A single comparable number (higher = more urgent) for sorting within/across buckets.
export function riskScore(x: RiskInput): number {
  const sev = { critical: 3, high: 2, medium: 1, low: 0 }[x.severity] ?? 0;
  return (x.kev ? 1000 : 0) + (x.exposure === 'public' ? 100 : 0) + (x.epss ?? 0) * 200 + sev;
}
