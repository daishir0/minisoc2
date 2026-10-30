'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { randomUUID } from 'node:crypto';
import { disableTotp, enableTotp, getTotp, requireUser, startTotpSecret } from '@/lib/auth';
import { verifyTotp } from '@/lib/totp';
import { pollPull, safePath } from '@/lib/pullssh';
import { recordEvent } from '@/lib/events';
import { q } from '@/lib/db';
import { sendMail } from '@/lib/mail';
import { randomToken, sha256hex } from '@/lib/secrets';
import { VEX_JUSTIFICATIONS } from '@/lib/vex';
import { parseTaskKey } from '@/lib/tasks';
import { encryptPassword, getMail, getPolicy, setSetting, type MailSettings, type PolicySettings } from '@/lib/settings';
import { parseAllowList } from '@/lib/ipallow';

export type Result = { ok?: string; error?: string; token?: string };

export async function createEnrollToken(_: Result, fd: FormData): Promise<Result> {
  await requireUser();
  const token = `enr_${randomToken(24)}`;
  const hours = Math.min(24 * 30, Math.max(1, Number(fd.get('hours') ?? 24)));
  const uses = Math.min(1000, Math.max(1, Number(fd.get('uses') ?? 1)));
  await q("INSERT INTO enroll_tokens(token_hash, label, max_uses, expires_at) VALUES ($1,$2,$3, now() + ($4 || ' hours')::interval)", [
    sha256hex(token), String(fd.get('label') ?? '').slice(0, 100), uses, String(hours),
  ]);
  revalidatePath('/enroll');
  return { token };
}

export async function revokeEnrollToken(id: number): Promise<void> {
  await requireUser();
  await q('DELETE FROM enroll_tokens WHERE id=$1', [id]);
  revalidatePath('/enroll');
}

export async function saveMail(_: Result, fd: FormData): Promise<Result> {
  await requireUser();
  const cur = await getMail();
  const pw = String(fd.get('password') ?? '');
  const next: MailSettings = {
    enabled: fd.get('enabled') === 'on',
    host: String(fd.get('host') ?? '').trim(),
    port: Number(fd.get('port') ?? 587),
    secure: fd.get('secure') === 'on',
    user: String(fd.get('user') ?? '').trim(),
    passwordEnc: pw ? encryptPassword(pw.replace(/\s+/g, '')) : cur.passwordEnc, // Gmail shows app passwords with spaces
    from: String(fd.get('from') ?? '').trim(),
    to: String(fd.get('to') ?? '').trim(),
  };
  await setSetting('mail', next);
  if (fd.get('test') === '1') {
    try {
      await sendMail('[minisoc2] テストメール', 'minisoc2 からのテストメールです。メール通知は正しく届いています。', next);
      return { ok: `保存しました。${next.to} にテストメールを送りました。${next.enabled ? '' : '（「アラートをメールで送る」がオフなので、アラートはまだ送られません）'}` };
    } catch (e) {
      return { error: `保存しましたが、テストメールの送信に失敗しました：${e instanceof Error ? e.message : String(e)}` };
    }
  }
  revalidatePath('/settings');
  return { ok: '保存しました。' };
}

export async function savePolicy(_: Result, fd: FormData): Promise<Result> {
  await requireUser();
  const cur = await getPolicy();
  const num = (k: string, min: number, max: number, d: number) => {
    const n = Number(fd.get(k));
    return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.round(n))) : d;
  };
  const sev = String(fd.get('notifyMinSeverity'));
  const next: PolicySettings = {
    notifyMinSeverity: (['critical', 'high', 'medium', 'low'].includes(sev) ? sev : cur.notifyMinSeverity) as PolicySettings['notifyMinSeverity'],
    notifyKev: fd.get('notifyKev') === 'on',
    staleHours: num('staleHours', 1, 24 * 30, cur.staleHours),
    fullRematchHour: num('fullRematchHour', 0, 23, cur.fullRematchHour),
    logRetentionDays: num('logRetentionDays', 1, 3650, cur.logRetentionDays),
    diskGuardPercent: num('diskGuardPercent', 50, 99, cur.diskGuardPercent),
    digestHour: num('digestHour', -1, 23, cur.digestHour ?? 8),
    ignoreIps: String(fd.get('ignoreIps') ?? '').split(/[\s,]+/).map((x) => x.trim()).filter((x) => /^[0-9a-fA-F:.]+$/.test(x)).slice(0, 200),
    osvCacheHours: num('osvCacheHours', 1, 168, cur.osvCacheHours),
    defaultAllowedIps: parseAllowList(String(fd.get('defaultAllowedIps') ?? '')).ok.slice(0, 200),
  };
  await setSetting('policy', next);
  revalidatePath('/settings');
  const bad = parseAllowList(String(fd.get('defaultAllowedIps') ?? '')).bad;
  return { ok: bad.length ? `保存しました。無効な許可IPは無視しました：${bad.slice(0, 5).join(', ')}` : '保存しました。' };
}

// --- Pull-type (read-only SSH) hosts ---
export async function addPullHost(_: Result, fd: FormData): Promise<Result> {
  await requireUser();
  const str = (k: string, max = 300) => String(fd.get(k) ?? '').trim().slice(0, max);
  const name = str('name', 200) || str('sshHost', 200);
  const sshHost = str('sshHost', 200);
  const sshUser = str('sshUser', 64);
  const port = Math.min(65535, Math.max(1, Number(fd.get('sshPort') ?? 22) || 22));
  const auth = str('auth') === 'password' ? 'password' : 'key';
  const secret = String(fd.get('secret') ?? '');
  const lines = (k: string) => String(fd.get(k) ?? '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean).slice(0, 100);
  const scanPaths = lines('scanPaths');
  const logGlobs = lines('logGlobs');
  if (!sshHost || !sshUser || !secret) return { error: 'SSHホスト・ユーザー・鍵またはパスワードは必須です。' };
  for (const p of [...scanPaths, ...logGlobs]) if (!safePath(p)) return { error: `使用できない文字を含むパスがあります：${p}` };
  const id = randomUUID();
  await q("INSERT INTO hosts(id, name, hostname, token_hash, kind, platform, os_id) VALUES ($1,$2,$3,$4,'pull','linux','')", [id, name, sshHost, sha256hex(randomToken())]);
  await q(
    `INSERT INTO pull_targets(host_id, ssh_host, ssh_port, ssh_user, auth, secret_enc, scan_paths, log_globs)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, sshHost, port, sshUser, auth, encryptPassword(secret), scanPaths, logGlobs],
  );
  await opsEvent(`プル型ホスト「${name}」を登録（${sshUser}@${sshHost}）`, id);
  try {
    await pollPull(id); // initial connection test + first collection; errors are stored on the target
  } catch {
    /* shown as last_error on the host page */
  }
  redirect(`/hosts/${id}`);
}

export async function savePullAide(fd: FormData): Promise<void> {
  await requireUser();
  const id = String(fd.get('id'));
  if (!/^[0-9a-f-]{36}$/.test(id)) return;
  const lines = (k: string) => String(fd.get(k) ?? '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean).filter(safePath).slice(0, 100);
  await q('UPDATE pull_targets SET aide_paths=$2, aide_excludes=$3 WHERE host_id=$1', [id, lines('aidePaths'), lines('aideExcludes')]);
  await opsEvent('プル型ホストの改ざん監視ディレクトリ設定を更新', id);
  revalidatePath(`/hosts/${id}`);
}

// Queue an on-demand collection for a push host; its next check-in (within a few minutes) runs it.
export async function requestCollect(fd: FormData): Promise<void> {
  await requireUser();
  const id = String(fd.get('id'));
  if (!/^[0-9a-f-]{36}$/.test(id)) return;
  await q("UPDATE hosts SET collect_requested=true WHERE id=$1 AND kind<>'pull'", [id]);
  await opsEvent('今すぐ収集を要求（次回チェックインで実行）', id);
  revalidatePath(`/hosts/${id}`);
}

export async function pollPullNow(fd: FormData): Promise<void> {
  await requireUser();
  const id = String(fd.get('id'));
  if (!/^[0-9a-f-]{36}$/.test(id)) return;
  const r = await pollPull(id);
  await opsEvent(`プル型ホストを即時収集：${r.ok ? `パッケージ${r.packages}・ログ${r.logs}行` : `失敗（${r.error}）`}`, id);
  revalidatePath(`/hosts/${id}`);
}

// --- Admin two-factor (TOTP) ---
export async function startTotp(): Promise<void> {
  const u = await requireUser();
  await startTotpSecret(u.id);
  revalidatePath('/settings');
  redirect('/settings?totp=setup');
}

export async function confirmTotp(fd: FormData): Promise<void> {
  const u = await requireUser();
  const code = String(fd.get('code') ?? '').trim();
  const { secret } = await getTotp(u.id);
  if (secret && verifyTotp(secret, code)) {
    await enableTotp(u.id);
    await opsEvent('2段階認証を有効化');
    redirect('/settings?totp=done');
  }
  redirect('/settings?totp=bad');
}

export async function disableTotp2fa(fd: FormData): Promise<void> {
  const u = await requireUser();
  // require a current valid code to turn it off (prevents an open session from silently disabling it)
  const code = String(fd.get('code') ?? '').trim();
  const { enabled, secret } = await getTotp(u.id);
  if (enabled && secret && !verifyTotp(secret, code)) {
    redirect('/settings?totp=bad');
  }
  await disableTotp(u.id);
  await opsEvent('2段階認証を無効化');
  redirect('/settings?totp=off');
}

export async function setAlertStatus(ids: string[], status: 'open' | 'ack' | 'resolved'): Promise<void> {
  await requireUser();
  await q('UPDATE alerts SET status=$2 WHERE id = ANY($1::bigint[])', [ids, status]);
  revalidatePath('/alerts');
}

export async function alertFormAction(fd: FormData): Promise<void> {
  const ids = fd.getAll('id').map(String);
  const status = String(fd.get('status')) as 'open' | 'ack' | 'resolved';
  if (ids.length && ['open', 'ack', 'resolved'].includes(status)) await setAlertStatus(ids, status);
}

export async function ackAllOpen(): Promise<void> {
  await requireUser();
  await q("UPDATE alerts SET status='ack' WHERE status='open'");
  revalidatePath('/alerts');
}

// VEX-style suppression: the finding stays recorded with a justification.
export async function suppressFinding(fd: FormData): Promise<void> {
  await requireUser();
  const id = String(fd.get('id'));
  const reason = String(fd.get('reason'));
  if (fd.get('undo') === '1') {
    await q("UPDATE findings SET status='open', suppress_reason=NULL, suppress_note=NULL, suppressed_at=NULL WHERE id=$1 AND status='suppressed'", [id]);
    await opsEvent(`脆弱性を未対応に戻しました（#${id}）`);
  } else if ((VEX_JUSTIFICATIONS as readonly string[]).includes(reason)) {
    const r = await q<{ vuln_id: string; pkg: string; host_id: string }>("UPDATE findings SET status='suppressed', suppress_reason=$2, suppress_note=$3, suppressed_at=now() WHERE id=$1 RETURNING vuln_id, pkg, host_id", [id, reason, String(fd.get('note') ?? '').slice(0, 1000)]);
    if (r[0]) await opsEvent(`${r[0].vuln_id}（${r[0].pkg}）を「影響なし」と判断（${reason}）`, r[0].host_id);
  }
  revalidatePath('/findings');
}

export async function addWatch(_: Result, fd: FormData): Promise<Result> {
  await requireUser();
  const cve = String(fd.get('cve') ?? '').trim().toUpperCase();
  if (!/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/i.test(cve)) return { error: 'CVE-2026-12345 のような形式で入力してください。' };
  await q('INSERT INTO watch_cves(cve, note) VALUES ($1,$2) ON CONFLICT (cve) DO UPDATE SET note=EXCLUDED.note', [cve, String(fd.get('note') ?? '').slice(0, 500)]);
  await q('UPDATE hosts SET needs_match=true WHERE NOT disabled');
  await opsEvent(`${cve} を CVE監視に追加`);
  revalidatePath('/watch');
  return { ok: `${cve} の監視を始めました。1分以内に全ホストを再照合します。` };
}

export async function removeWatch(fd: FormData): Promise<void> {
  await requireUser();
  await q('DELETE FROM watch_cves WHERE cve=$1', [String(fd.get('cve'))]);
  await opsEvent(`${String(fd.get('cve'))} を CVE監視から解除`);
  revalidatePath('/watch');
}

export async function hostAction(fd: FormData): Promise<void> {
  await requireUser();
  const id = String(fd.get('id'));
  const op = String(fd.get('op'));
  if (op === 'rename') await q('UPDATE hosts SET name=$2 WHERE id=$1', [id, String(fd.get('name') ?? '').slice(0, 200) || 'unnamed']);
  if (op === 'allowips') {
    const ips = parseAllowList(String(fd.get('allowedIps') ?? '')).ok.slice(0, 200);
    await q('UPDATE hosts SET allowed_ips=$2 WHERE id=$1', [id, ips]);
    await opsEvent(`ホストの許可IPを更新（${ips.length ? ips.length + '件' : '制限なし'}）`, id);
  }
  if (op === 'disable') await q('UPDATE hosts SET disabled=true WHERE id=$1', [id]);
  if (op === 'enable') await q('UPDATE hosts SET disabled=false, needs_match=true WHERE id=$1', [id]);
  if (op === 'rematch') await q('UPDATE hosts SET needs_match=true WHERE id=$1', [id]);
  if (op === 'delete' && fd.get('confirm') === 'delete') {
    await q('DELETE FROM raw_logs WHERE host_id=$1', [id]); // partitioned table has no FK cascade
    await q('DELETE FROM hosts WHERE id=$1', [id]);
  }
  revalidatePath('/hosts');
  revalidatePath(`/hosts/${id}`);
}

export async function systemAction(fd: FormData): Promise<void> {
  await requireUser();
  const id = Number(fd.get('id'));
  const op = String(fd.get('op'));
  if (op === 'rename') await q('UPDATE systems SET name=$2 WHERE id=$1', [id, String(fd.get('name') ?? '').trim().slice(0, 200) || 'unnamed']);
  if (op === 'ignore' || op === 'watch') {
    const r = await q<{ host_id: string; name: string }>("UPDATE systems SET ignored=$2 WHERE id=$1 AND root <> '__os__' RETURNING host_id, name", [id, op === 'ignore']);
    if (r[0]) {
      await q('UPDATE hosts SET needs_match=true WHERE id=$1', [r[0].host_id]);
      await opsEvent(`システム「${r[0].name}」を${op === 'ignore' ? '除外' : '監視に戻す'}`, r[0].host_id);
    }
  }
  revalidatePath('/systems');
}

// Host-specific system roots, one per line ("/srv/apps/*" = every child directory is a system).
export async function saveSystemRoots(fd: FormData): Promise<void> {
  await requireUser();
  const id = String(fd.get('id'));
  const roots = String(fd.get('roots') ?? '').split(/\r?\n/).map((x) => x.trim()).filter((x) => /^(\/|[A-Za-z]:\\)/.test(x)).slice(0, 200);
  await q('UPDATE hosts SET system_roots=$2 WHERE id=$1', [id, roots]);
  revalidatePath(`/hosts/${id}`);
}

export async function watchCve(fd: FormData): Promise<void> {
  await requireUser();
  const cve = String(fd.get('cve') ?? '').trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) return;
  await q("INSERT INTO watch_cves(cve, note) VALUES ($1, 'CVE照会から追加') ON CONFLICT DO NOTHING", [cve]);
  await q('UPDATE hosts SET needs_match=true WHERE NOT disabled');
  revalidatePath(`/cve/${cve}`);
  revalidatePath('/watch');
}

// Create or update a system record. Manual roots decide how packages are grouped from the next report.
export async function saveSystem(fd: FormData): Promise<void> {
  await requireUser();
  const id = Number(fd.get('id') || 0);
  const str = (k: string, max = 300) => String(fd.get(k) ?? '').trim().slice(0, max);
  const pick = (k: string, allowed: string[], d: string) => (allowed.includes(str(k)) ? str(k) : d);
  const attrs = [
    str('name', 200) || 'unnamed',
    pick('exposure', ['public', 'internal', 'dev', 'unknown'], 'unknown'),
    pick('criticality', ['high', 'normal', 'low'], 'normal'),
    str('url', 500), str('owner', 200), str('stack', 200), str('note', 2000),
    fd.get('monitored') !== 'on',
  ];
  let hostId: string;
  let sysId = id;
  if (id) {
    // Saving via this form registers the project. If it was still auto-detected, reset its baseline
    // so its first evaluation summarises existing findings once instead of alerting each one.
    const r = await q<{ host_id: string }>(
      `UPDATE systems SET name=$2, exposure=$3, criticality=$4, url=$5, owner=$6, stack=$7, note=$8, ignored=$9,
         origin='manual', baselined = CASE WHEN origin='auto' THEN false ELSE baselined END
       WHERE id=$1 RETURNING host_id`,
      [id, ...attrs],
    );
    if (!r[0]) return;
    hostId = r[0].host_id;
    const root = str('root', 1000);
    if (root && /^(\/|[A-Za-z]:\\)/.test(root)) {
      await q("UPDATE systems SET root=$2 WHERE id=$1 AND root <> '__os__' AND root <> $2", [id, root.replace(/[\\/]+$/, '')]);
    }
  } else {
    hostId = str('host', 40);
    const root = str('root', 1000).replace(/[\\/]+$/, '');
    if (!/^[0-9a-f-]{36}$/.test(hostId) || !/^(\/|[A-Za-z]:\\)/.test(root)) return;
    const r = await q<{ id: number }>(
      `INSERT INTO systems(host_id, root, name, exposure, criticality, url, owner, stack, note, ignored, origin, baselined)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'manual',false)
       ON CONFLICT (host_id, root) DO UPDATE SET origin='manual', name=EXCLUDED.name, exposure=EXCLUDED.exposure, criticality=EXCLUDED.criticality,
         url=EXCLUDED.url, owner=EXCLUDED.owner, stack=EXCLUDED.stack, note=EXCLUDED.note, ignored=EXCLUDED.ignored,
         baselined = CASE WHEN systems.origin='auto' THEN false ELSE systems.baselined END
       RETURNING id`,
      [hostId, root, ...attrs],
    );
    sysId = r[0].id;
  }
  await q('UPDATE hosts SET needs_match=true WHERE id=$1', [hostId]);
  await opsEvent(`システム「${attrs[0]}」を${id ? '更新' : '登録'}`, hostId);
  revalidatePath('/systems');
  redirect(`/systems/${sysId}?saved=1`);
}

// Remove a project from monitoring: revert it to an auto-detected candidate (keeps its settings
// such as excludes/exposure, but it is no longer evaluated). Its open findings resolve on re-match.
export async function unregisterSystem(fd: FormData): Promise<void> {
  await requireUser();
  const id = Number(fd.get('id'));
  const r = await q<{ host_id: string; name: string }>("UPDATE systems SET origin='auto', baselined=true WHERE id=$1 AND origin='manual' AND root <> '__os__' RETURNING host_id, name", [id]);
  if (r[0]) {
    await q('UPDATE hosts SET needs_match=true WHERE id=$1', [r[0].host_id]);
    await opsEvent(`プロジェクト「${r[0].name}」を監視対象から外す（登録解除）`, r[0].host_id);
    revalidatePath('/hosts');
    revalidatePath(`/hosts/${r[0].host_id}`);
    redirect(`/hosts/${r[0].host_id}`);
  }
}

export async function deleteSystem(fd: FormData): Promise<void> {
  await requireUser();
  const id = Number(fd.get('id'));
  const r = await q<{ host_id: string }>("DELETE FROM systems WHERE id=$1 AND origin='manual' RETURNING host_id", [id]);
  if (r[0]) await q('UPDATE hosts SET needs_match=true WHERE id=$1', [r[0].host_id]);
  revalidatePath('/systems');
  redirect('/systems');
}

async function opsEvent(title: string, hostId?: string): Promise<void> {
  const u = await requireUser();
  await recordEvent({ hostId: hostId ?? null, kind: 'ops', important: false, title: `${title}（${u.email}）` });
}

export async function saveTask(fd: FormData): Promise<void> {
  await requireUser();
  const key = String(fd.get('key') ?? '');
  const k = parseTaskKey(key);
  if (!k) return;
  const status = ['todo', 'doing', 'hold'].includes(String(fd.get('status'))) ? String(fd.get('status')) : 'todo';
  const due = /^\d{4}-\d{2}-\d{2}$/.test(String(fd.get('due') ?? '')) ? String(fd.get('due')) : null;
  await q(
    `INSERT INTO tasks(host_id, system_root, status, owner, due_date, note, updated_at) VALUES ($1,$2,$3,$4,$5,$6, now())
     ON CONFLICT (host_id, system_root) DO UPDATE SET status=EXCLUDED.status, owner=EXCLUDED.owner, due_date=EXCLUDED.due_date, note=EXCLUDED.note, updated_at=now()`,
    [k.hostId, k.root, status, String(fd.get('owner') ?? '').slice(0, 100), due, String(fd.get('note') ?? '').slice(0, 2000)],
  );
  await opsEvent(`作業「${k.root === '__os__' ? 'OS' : k.root.split('/').pop()}」を${{ todo: '未着手', doing: '対応中', hold: '保留' }[status]}に変更`, k.hostId);
  revalidatePath('/actions');
  redirect(`/actions/${key}?saved=1`);
}

export async function taskNotAffected(fd: FormData): Promise<void> {
  await requireUser();
  const k = parseTaskKey(String(fd.get('key') ?? ''));
  const reason = String(fd.get('reason'));
  if (!k || !(VEX_JUSTIFICATIONS as readonly string[]).includes(reason)) return;
  const r = await q(
    `UPDATE findings SET status='suppressed', suppress_reason=$3, suppress_note=$4, suppressed_at=now()
     WHERE host_id=$1 AND status='open' AND (kev OR severity='critical')
       AND (CASE WHEN cardinality(systems)=0 THEN ARRAY['__os__'] ELSE systems END) @> ARRAY[$2] RETURNING id`,
    [k.hostId, k.root, reason, String(fd.get('note') ?? '').slice(0, 1000)],
  );
  await opsEvent(`作業「${k.root === '__os__' ? 'OS' : k.root.split('/').pop()}」の ${r.length}件を「影響なし」と判断（${reason}）`, k.hostId);
  revalidatePath('/actions');
  redirect('/actions');
}

export async function ackDetection(fd: FormData): Promise<void> {
  await requireUser();
  await q("UPDATE alerts SET status='ack' WHERE id=$1", [String(fd.get('id'))]);
  revalidatePath('/actions');
}

// "That was me": remember the IP so log rules stop alerting on it, and close the detection.
export async function trustIp(fd: FormData): Promise<void> {
  await requireUser();
  const ip = String(fd.get('ip') ?? '').trim();
  if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return;
  const policy = await getPolicy();
  if (!(policy.ignoreIps ?? []).includes(ip)) await setSetting('policy', { ...policy, ignoreIps: [...(policy.ignoreIps ?? []), ip] });
  await q("UPDATE alerts SET status='ack' WHERE status='open' AND kind='log' AND title LIKE $1", [`%${ip}%`]);
  await opsEvent(`${ip} を既知のIPとして登録`);
  revalidatePath('/actions');
}

export async function dismissOnboarding(): Promise<void> {
  await requireUser();
  await setSetting('onboarding', { dismissed: true });
  revalidatePath('/');
}

export async function addExclude(fd: FormData): Promise<void> {
  const u = await requireUser();
  const systemId = Number(fd.get('systemId'));
  const pattern = String(fd.get('pattern') ?? '').trim().replace(/^\.?\/+/, '').slice(0, 300);
  const reason = String(fd.get('reason') ?? '').trim().slice(0, 500);
  const review = /^\d{4}-\d{2}-\d{2}$/.test(String(fd.get('review') ?? '')) ? String(fd.get('review')) : null;
  if (!systemId || !pattern || !reason || pattern.includes('..')) return;
  const r = await q<{ host_id: string; name: string }>(
    `WITH ins AS (INSERT INTO system_excludes(system_id, pattern, reason, created_by, review_date) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (system_id, pattern) DO UPDATE SET reason=EXCLUDED.reason, review_date=EXCLUDED.review_date RETURNING system_id)
     SELECT s.host_id, s.name FROM systems s JOIN ins ON ins.system_id=s.id`,
    [systemId, pattern, reason, u.email, review],
  );
  if (r[0]) await opsEvent(`システム「${r[0].name}」で ${pattern} を除外（理由：${reason}）`, r[0].host_id);
  revalidatePath(`/systems/${systemId}`);
}

export async function removeExclude(fd: FormData): Promise<void> {
  await requireUser();
  const id = Number(fd.get('id'));
  const r = await q<{ system_id: number; pattern: string; host_id: string; name: string }>(
    `DELETE FROM system_excludes e USING systems s WHERE e.id=$1 AND s.id=e.system_id RETURNING e.system_id, e.pattern, s.host_id, s.name`, [id],
  );
  if (r[0]) {
    await opsEvent(`システム「${r[0].name}」の除外 ${r[0].pattern} を解除`, r[0].host_id);
    revalidatePath(`/systems/${r[0].system_id}`);
  }
}
