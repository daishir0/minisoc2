export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export type Severity = (typeof SEVERITIES)[number];

export function sevRank(s: string): number {
  const i = SEVERITIES.indexOf(s as Severity);
  return i < 0 ? SEVERITIES.length : i;
}

export function atLeast(s: string, min: string): boolean {
  return sevRank(s) <= sevRank(min);
}

export function fromScore(score: number | null): Severity {
  if (score == null) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

export function normalizeLabel(label: string | undefined): Severity {
  const l = (label ?? '').toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high' || l === 'important') return 'high';
  if (l === 'moderate' || l === 'medium') return 'medium';
  if (l === 'low') return 'low';
  return 'unknown';
}

// CVSS v3.x base score from a vector string (CVSS:3.1/AV:N/AC:L/...).
export function cvss3Score(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m: Record<string, string> = {};
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    m[k] = v;
  }
  const W: Record<string, Record<string, number>> = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    C: { H: 0.56, L: 0.22, N: 0 },
    I: { H: 0.56, L: 0.22, N: 0 },
    A: { H: 0.56, L: 0.22, N: 0 },
  };
  const changed = m.S === 'C';
  const PR = changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const vals = [W.AV[m.AV], W.AC[m.AC], (PR as Record<string, number>)[m.PR], W.UI[m.UI], W.C[m.C], W.I[m.I], W.A[m.A]];
  if (vals.some((v) => v === undefined)) return null;
  const [av, ac, pr, ui, c, i, a] = vals;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const raw = changed ? Math.min(1.08 * (impact + expl), 10) : Math.min(impact + expl, 10);
  return Math.ceil(raw * 10 - 1e-9) / 10;
}
