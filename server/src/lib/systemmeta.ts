// Labels and detection helpers for system attributes.
export const EXPOSURE: Record<string, string> = { public: '外部公開', internal: '社内・内部', dev: '開発・検証', unknown: '未設定' };
export const CRITICALITY: Record<string, string> = { high: '重要度 高', normal: '重要度 中', low: '重要度 低' };

// Package names that identify a framework, checked in order.
const STACK_MARKERS: [string, string][] = [
  ['npm:next', 'Next.js'], ['npm:expo', 'Expo'], ['npm:react-native', 'React Native'], ['npm:react', 'React'], ['npm:vue', 'Vue'],
  ['npm:express', 'Express'], ['PyPI:fastapi', 'FastAPI'], ['PyPI:flask', 'Flask'], ['PyPI:django', 'Django'], ['PyPI:streamlit', 'Streamlit'],
  ['Packagist:laravel/framework', 'Laravel'], ['Packagist:symfony/symfony', 'Symfony'],
];
export const STACK_KEYS = STACK_MARKERS.map(([k]) => k);

export function detectStack(markers: string[], ecosystems: string[]): string {
  const have = new Set(markers);
  const found = STACK_MARKERS.filter(([k]) => have.has(k)).map(([, v]) => v);
  // React is implied by Next.js / Expo / React Native
  const uniq = found.filter((v) => !(v === 'React' && found.some((x) => ['Next.js', 'Expo', 'React Native'].includes(x))));
  if (uniq.length) return uniq.slice(0, 3).join(' / ');
  if (ecosystems.includes('PyPI')) return 'Python';
  if (ecosystems.includes('npm')) return 'Node.js';
  if (ecosystems.includes('Packagist')) return 'PHP';
  return '';
}
