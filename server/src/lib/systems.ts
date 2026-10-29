// Which "system" (application / project) a package belongs to, from the lockfile path.
//   1. host-specific roots win (longest match); "/srv/apps/*" means each child directory is a system
//   2. otherwise the first directory under the agent's scan path ("/srv/projects/shop")
//   3. otherwise the lockfile's directory
// Packages from the OS package manager belong to the pseudo system "__os__".
export const OS_SYSTEM = '__os__';

export function systemOf(source: string, scanPaths: string[], roots: string[], pythonEnvs: string[] = []): string {
  if (!source.startsWith('/') && !/^[A-Za-z]:\\/.test(source)) return OS_SYSTEM;
  const sep = source.includes('\\') && !source.includes('/') ? '\\' : '/';
  const under = (base: string) => source.startsWith(base.replace(/[\\/]+$/, '') + sep);
  let best = '';
  for (const r of roots) {
    if (r.endsWith(`${sep}*`)) {
      const base = r.slice(0, -2);
      if (under(base)) {
        const next = source.slice(base.length + 1).split(sep)[0];
        const cand = `${base}${sep}${next}`;
        if (source !== cand && cand.length > best.length) best = cand;
      }
    } else if (under(r) && r.length > best.length) best = r.replace(/[\\/]+$/, '');
  }
  if (best) return best;
  // shared Python environments (conda) are systems of their own
  for (const env of [...pythonEnvs].sort((a, b) => b.length - a.length)) {
    if (under(env)) return env.replace(/[\\/]+$/, '');
  }
  for (const sp of [...scanPaths].sort((a, b) => b.length - a.length)) {
    const base = sp.replace(/[\\/]+$/, '');
    if (!under(base)) continue;
    const rest = source.slice(base.length + 1).split(sep);
    return rest.length > 1 ? `${base}${sep}${rest[0]}` : base;
  }
  return source.slice(0, source.lastIndexOf(sep)) || source;
}

export function defaultName(root: string, pythonEnvs: string[] = []): string {
  if (root === OS_SYSTEM) return 'OSパッケージ';
  if (pythonEnvs.includes(root)) return `Python環境（${root.split(/[\\/]/).filter(Boolean).pop()}）`;
  return root.split(/[\\/]/).filter(Boolean).pop() ?? root;
}

// Glob relative to a system root: "**" spans directories, "*" stays within one segment.
export function globToRegExp(pattern: string): RegExp {
  const p = pattern.trim().replace(/^\.?\/+/, '').replace(/\/+$/, '');
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i];
    if (ch === '*' && p[i + 1] === '*') {
      re += '.*';
      i++;
      if (p[i + 1] === '/') i++;
    } else if (ch === '*') re += '[^/]*';
    else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  // a plain directory pattern ("data") also covers everything below it
  return new RegExp(`^${re}(?:/.*)?$`);
}

// The exclusion pattern (if any) that covers a lockfile / dist-info path inside a system.
export function excludedBy(source: string, root: string, rules: { pattern: string; re: RegExp }[]): string | null {
  const base = root.replace(/[\\/]+$/, '');
  if (!source.startsWith(base + '/')) return null;
  const rel = source.slice(base.length + 1);
  return rules.find((r) => r.re.test(rel))?.pattern ?? null;
}

// Which application a service belongs to (by working directory), or null for system daemons.
export function serviceSystem(cwd: string, scanPaths: string[], roots: string[]): string | null {
  if (!cwd || !cwd.startsWith('/')) return null;
  const dir = cwd.replace(/\/+$/, '');
  const inside = (base: string) => dir === base || dir.startsWith(base + '/');
  const manual = roots.filter((r) => !r.endsWith('/*') && inside(r.replace(/\/+$/, ''))).sort((a, b) => b.length - a.length)[0];
  if (manual) return manual.replace(/\/+$/, '');
  for (const sp of [...scanPaths].sort((a, b) => b.length - a.length)) {
    const base = sp.replace(/\/+$/, '');
    if (dir.startsWith(base + '/')) return `${base}/${dir.slice(base.length + 1).split('/')[0]}`;
  }
  return null;
}

// The shared Python environment a service runs on (conda env by name or by interpreter path).
export function serviceRuntime(bin: string, condaEnv: string | undefined, pythonEnvs: string[], systemRoot: string | null): string | null {
  if (condaEnv) {
    const hit = condaEnv === 'base'
      ? pythonEnvs.find((e) => !/\/envs\//.test(e))
      : pythonEnvs.find((e) => e.endsWith(`/envs/${condaEnv}`));
    if (hit) return hit;
  }
  if (systemRoot && bin.startsWith(systemRoot + '/')) return null; // its own venv
  return [...pythonEnvs].sort((a, b) => b.length - a.length).find((e) => bin.startsWith(e.replace(/\/+$/, '') + '/')) ?? null;
}

export function serviceOsPackage(execPkg: string | undefined): string | null {
  if (!execPkg || ['bash', 'coreutils', 'dash', 'zsh', 'systemd'].includes(execPkg)) return null;
  return execPkg.replace(/-npm$/, ''); // npm runs on the nodejs package
}
