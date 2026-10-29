// Running services and what they execute: the link between applications, shared runtimes
// (conda / venv) and OS packages (nodejs, python, httpd ...).
import { realpathSync } from 'node:fs';
import type { CollectError, ServiceInfo } from '../types.js';
import { run } from '../util.js';

function parseExec(v: string): { exec: string; argv: string } {
  const path = v.match(/path=([^ ;]+)/)?.[1] ?? '';
  const argv = v.match(/argv\[\]=([^;]+)/)?.[1]?.trim() ?? '';
  return { exec: path, argv };
}

// The interpreter actually used, also through "bash -c 'source .../activate 311 && exec python app.py'".
function interpreter(exec: string, argv: string): { bin: string; condaEnv?: string } {
  const act = argv.match(/activate\s+([\w.-]+)/);
  const abs = argv.match(/(\/[^\s'"]*\/(?:python[\d.]*|node|uvicorn|gunicorn|php[\d.]*|java|ruby))(?=\s|$|'|")/);
  if (/\/(ba|z|da)?sh$/.test(exec) && abs) return { bin: abs[1], condaEnv: act?.[1] };
  return { bin: exec, condaEnv: act?.[1] };
}

export async function linuxServices(errors: CollectError[]): Promise<ServiceInfo[]> {
  const list = await run('systemctl', ['list-units', '--type=service', '--state=running', '--no-legend', '--plain', '--no-pager'], 30_000);
  if (!list.ok) {
    errors.push({ step: 'services', message: (list.stderr || 'systemctl failed').slice(0, 200) });
    return [];
  }
  const units = list.stdout.split('\n').map((l) => l.trim().split(/\s+/)[0]).filter((u) => u.endsWith('.service'));
  if (!units.length) return [];
  const show = await run('systemctl', ['show', ...units, '-p', 'Id', '-p', 'ExecStart', '-p', 'WorkingDirectory', '-p', 'User', '--no-pager'], 30_000);
  const out: ServiceInfo[] = [];
  for (const block of show.stdout.split(/\n\s*\n/)) {
    const get = (k: string) => block.match(new RegExp(`^${k}=(.*)$`, 'm'))?.[1]?.trim() ?? '';
    const name = get('Id');
    if (!name) continue;
    const { exec, argv } = parseExec(get('ExecStart'));
    const it = interpreter(exec, argv);
    // keep the path as written (a venv's python is a symlink to the base interpreter);
    // the resolved path is only used to find the owning OS package
    let real = it.bin;
    try {
      real = realpathSync(it.bin);
    } catch {
      /* not readable */
    }
    out.push({ name, cwd: get('WorkingDirectory'), exec, argv: argv.slice(0, 500), user: get('User') || 'root', bin: it.bin, realBin: real, condaEnv: it.condaEnv });
  }
  // which OS package owns each executable
  const bins = [...new Set(out.map((s) => s.realBin ?? s.bin).filter((b) => b.startsWith('/usr/') || b.startsWith('/bin/') || b.startsWith('/sbin/')))];
  if (bins.length) {
    const rpm = await run('rpm', ['-qf', '--qf', '%{NAME}\\n', ...bins], 30_000);
    const owners = rpm.stdout.split('\n');
    if (rpm.stdout.trim()) bins.forEach((b, i) => {
      const o = owners[i]?.trim();
      if (o && !/not owned|is not/.test(o)) for (const s of out) if ((s.realBin ?? s.bin) === b) s.execPkg = o;
    });
    else {
      const dpkg = await run('dpkg', ['-S', ...bins], 30_000);
      for (const line of dpkg.stdout.split('\n')) {
        const m = line.match(/^([^:]+):\S*\s+(\S+)$/);
        if (m) for (const s of out) if ((s.realBin ?? s.bin) === m[2]) s.execPkg = m[1];
      }
    }
  }
  // npm / npx / next scripts run on whatever "node" is on PATH: attribute them to its package
  const nodeLike = out.filter((x) => (!x.execPkg || ['bash', 'dash', 'zsh'].includes(x.execPkg)) && (/\/node_modules\/|\/(npm|npx|next|node)(-cli\.js)?$/.test(x.bin) || /(^|[\s/])(npm|npx|node)\s/.test(x.argv)));
  if (nodeLike.length) {
    const which = await run('sh', ['-c', 'readlink -f "$(command -v node)"'], 10_000);
    const nodeBin = which.stdout.trim();
    if (nodeBin.startsWith('/usr/')) {
      const o = (await run('rpm', ['-qf', '--qf', '%{NAME}', nodeBin], 10_000)).stdout.trim();
      if (o && !/not owned/.test(o)) for (const x of nodeLike) x.execPkg = o;
    }
  }
  return out;
}
