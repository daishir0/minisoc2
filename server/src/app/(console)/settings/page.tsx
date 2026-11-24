import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import QRCode from 'qrcode';
import { ActionForm } from '@/components/ActionForm';
import { Card, SEV_LABEL } from '@/components/ui';
import { currentUser, getTotp, listUsers } from '@/lib/auth';
import { otpauthURL } from '@/lib/totp';
import { getMail, getPolicy, type SevLevel } from '@/lib/settings';
import { q } from '@/lib/db';
import { Masked } from '@/components/Mask';
import { confirmTotp, disableTotp2fa, saveMail, savePolicy, startTotp, addUserAction, deleteUserAction, resetUserPasswordAction } from '../actions';

const USER_MSG: Record<string, string> = {
  deleted: 'ユーザーを削除しました。', pwreset: 'パスワードを再設定しました（対象ユーザーは次回ログインから新パスワード）。',
  self: '自分自身は削除できません。', last: '最後の管理者は削除できません。', pwerr: 'パスワードは8文字以上にしてください。',
};

// The action-line options, with the cumulative "how many findings this would make actionable" shown inline
// so the impact of each choice is visible before saving.
const LEVELS: { v: SevLevel; label: string }[] = [
  { v: 'critical', label: '緊急（CVSS 9.0以上）' }, { v: 'high', label: '高 以上' }, { v: 'medium', label: '中 以上' }, { v: 'low', label: '低 以上（すべて）' },
];
function levelSelect(name: string, value: SevLevel, cum: Record<SevLevel, number>) {
  return (
    <select name={name} defaultValue={value} className="input">
      {LEVELS.map((l) => <option key={l.v} value={l.v}>{l.label} — 対象 {cum[l.v]}件（KEV含む）</option>)}
    </select>
  );
}

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-muted">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export default async function SettingsPage({ searchParams }: { searchParams: Promise<{ totp?: string; user?: string }> }) {
  const mail = await getMail();
  const p = await getPolicy();
  // Cumulative open-finding counts per action line, so each dropdown option shows its real impact.
  const [sc] = await q<{ kev: string; crit: string; high: string; med: string; low: string }>(
    `SELECT count(*) FILTER (WHERE kev) kev,
            count(*) FILTER (WHERE NOT kev AND severity='critical') crit,
            count(*) FILTER (WHERE NOT kev AND severity='high') high,
            count(*) FILTER (WHERE NOT kev AND severity='medium') med,
            count(*) FILTER (WHERE NOT kev AND severity='low') low
     FROM findings WHERE status='open'`);
  const n = { kev: Number(sc?.kev ?? 0), crit: Number(sc?.crit ?? 0), high: Number(sc?.high ?? 0), med: Number(sc?.med ?? 0), low: Number(sc?.low ?? 0) };
  const cum: Record<SevLevel, number> = {
    critical: n.kev + n.crit,
    high: n.kev + n.crit + n.high,
    medium: n.kev + n.crit + n.high + n.med,
    low: n.kev + n.crit + n.high + n.med + n.low,
  };
  const { totp: totpState, user: userMsg } = await searchParams;
  const user = await currentUser();
  const users = await listUsers();
  const totp = user ? await getTotp(user.id) : { enabled: false, secret: '' };
  const qrSvg = totpState === 'setup' && user && totp.secret && !totp.enabled
    ? await QRCode.toString(otpauthURL(user.email, totp.secret), { type: 'svg', margin: 1, width: 192 })
    : '';
  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: '設定' }]} />
    <div className="grid gap-6 lg:grid-cols-2">
      <Card title="メール通知（Gmail）">
        <p className="mb-4 text-sm text-muted">
          Gmail の SMTP を<b>アプリパスワード</b>で使います（Google アカウント → セキュリティ → 2段階認証プロセス → アプリパスワード）。パスワードは暗号化して保存します。
        </p>
        <ActionForm action={saveMail} className="space-y-3">
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="enabled" defaultChecked={mail.enabled} /> 通知をメールで送る</label>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2"><Field label="SMTPサーバー"><input name="host" className="input" defaultValue={mail.host} /></Field></div>
            <Field label="ポート"><input name="port" type="number" className="input" defaultValue={mail.port} /></Field>
          </div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="secure" defaultChecked={mail.secure} /> SSL/TLS で接続（ポート465）。587番の STARTTLS ならオフのまま。</label>
          <Field label="Gmailアドレス（SMTPユーザー）" hint="アプリパスワードを発行したGmailアカウント。空欄なら差出人のアドレスを使います。"><input name="user" type="email" className="input" defaultValue={mail.user} placeholder={mail.from || 'you@gmail.com'} /></Field>
          <Field label="アプリパスワード" hint={mail.passwordEnc ? '保存済みです。変更しない場合は空欄のままにしてください。' : '未設定です。'}><input name="password" type="password" className="input" autoComplete="new-password" /></Field>
          <Field label="差出人（任意）"><input name="from" className="input" defaultValue={mail.from} placeholder="minisoc2 <you@gmail.com>" /></Field>
          <Field label="通知先" hint="複数ある場合はカンマ区切り。"><input name="to" className="input" defaultValue={mail.to} /></Field>
          <div className="flex gap-2">
            <button className="btn" name="test" value="0">保存</button>
            <button className="btn-ghost" name="test" value="1">保存してテストメールを送る</button>
          </div>
        </ActionForm>
      </Card>
      <Card title="検知と通知のルール">
        <ActionForm action={savePolicy} className="space-y-3">
          <div className="rounded-md border border-line bg-bg p-3">
            <p className="mb-2 text-sm font-semibold">対応レベル（深刻度ライン）</p>
            <p className="mb-3 text-xs text-muted">「これ以上の深刻度を"要対応"として扱う」ラインです。画面とメールで別々に設定できます。各選択肢に<b>今その設定なら何件が対象になるか</b>を表示しています（現在 開いている脆弱性：緊急{n.crit}・高{n.high}・中{n.med}・低{n.low}、KEV{n.kev}）。</p>
            <div className="space-y-3">
              <Field label="対応ライン（画面）" hint="ホーム「今日やる」・緊急カウント・脆弱性タブの既定・各バッジに反映。">{levelSelect('screenLevel', p.screenLevel, cum)}</Field>
              <Field label="即時メールの深刻度" hint="これ未満は日次まとめに回します。">{levelSelect('mailLevel', p.mailLevel, cum)}</Field>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="notifyKev" defaultChecked={p.notifyKev} /> 悪用が確認された脆弱性（CISA KEV）は深刻度にかかわらずメール・要対応にする</label>
              <label className="flex items-start gap-2 text-sm"><input type="checkbox" name="watchAlwaysImmediate" defaultChecked={p.watchAlwaysImmediate} className="mt-1" /> <span>ウォッチ登録CVEは深刻度に関係なく即時メール<br /><span className="text-xs text-muted">オフ時：「修正版が出た／解消」のときは即時、ただの「検出」は上の即時メール深刻度に従います。</span></span></label>
            </div>
          </div>
          <Field label="日次まとめメールの時刻（時、サーバー時刻）" hint="全ホストの未対応件数（KEV/緊急/高/新規/監視）を1通にまとめ、毎日この時刻に送ります（0件のホストも表示）。-1 で停止。"><input name="digestHour" type="number" className="input" defaultValue={p.digestHour ?? 8} /></Field>
          <Field label="報告が途絶えたらアラートを出すまでの時間（時間）"><input name="staleHours" type="number" className="input" defaultValue={p.staleHours} /></Field>
          <Field label="全ホストを毎日再照合する時刻（時、サーバー時刻）" hint="ソフトが変わっていなくても、新しく公表されたCVEを拾います。"><input name="fullRematchHour" type="number" className="input" defaultValue={p.fullRematchHour} /></Field>
          <Field label="OSV照合結果のキャッシュ（時間）"><input name="osvCacheHours" type="number" className="input" defaultValue={p.osvCacheHours} /></Field>
          <Field label="生ログの保存期間（日）" hint="ログ監視で使います。集計値は期間に関係なく永続的に保存します。"><input name="logRetentionDays" type="number" className="input" defaultValue={p.logRetentionDays} /></Field>
          <Field label="ログ検知で無視するIP" hint="自分のサーバーや監視サービスのIPなど。スペース・カンマ・改行区切り。"><textarea name="ignoreIps" rows={2} className="input font-mono" defaultValue={(p.ignoreIps ?? []).join('\n')} /></Field>
          <Field label="既定の許可接続元IP（全ホスト共通）" hint="エージェント/SSHの接続を許可するIP・CIDR（例 203.0.113.0/24）。改行かカンマ区切り。空欄なら制限なし。ホストごとに個別設定した場合はそちらが優先されます。"><textarea name="defaultAllowedIps" rows={2} className="input font-mono" defaultValue={(p.defaultAllowedIps ?? []).join('\n')} placeholder="203.0.113.0/24&#10;2001:db8::/32" /></Field>
          <Field label="ディスク使用率の上限（%）" hint="超えると生ログの保存を一時停止します（ルール判定と集計は続けます）。"><input name="diskGuardPercent" type="number" className="input" defaultValue={p.diskGuardPercent} /></Field>
          <button className="btn">保存</button>
        </ActionForm>
      </Card>
      <Card title="ユーザー管理">
        <p className="mb-3 text-sm text-muted">ログインできる管理者です。<b>全員が同じ権限（管理者）</b>で、各自が自分のメール・パスワード・2段階認証を持ちます。操作は「変化の履歴（運用の記録）」に実行者付きで残ります。</p>
        {userMsg && USER_MSG[userMsg] && <p className={`mb-3 text-sm ${['self', 'last', 'pwerr'].includes(userMsg) ? 'text-red-600' : 'text-green-600'}`}>{USER_MSG[userMsg]}</p>}
        <div className="overflow-x-auto">
          <table className="tbl"><thead><tr><th>メール</th><th>2FA</th><th>最終ログイン</th><th>操作</th></tr></thead><tbody>
            {users.map((uu) => (
              <tr key={uu.id}>
                <td className="break-all"><Masked kind="email">{uu.email}</Masked>{uu.id === user?.id && <span className="ml-1 text-xs text-muted">（自分）</span>}</td>
                <td className="whitespace-nowrap text-xs">{uu.totp_enabled ? '✅ 有効' : '—'}</td>
                <td className="whitespace-nowrap text-xs text-muted">{uu.last_login_at ? new Date(uu.last_login_at).toLocaleString('ja-JP') : '未ログイン'}</td>
                <td>
                  <div className="flex flex-wrap items-center gap-2">
                    <form action={resetUserPasswordAction} className="flex items-center gap-1">
                      <input type="hidden" name="id" value={uu.id} />
                      <input name="password" type="text" className="input h-7 w-36 text-xs" placeholder="新しいパスワード" autoComplete="off" />
                      <button className="btn-ghost text-xs">再設定</button>
                    </form>
                    {uu.id !== user?.id && (
                      <form action={deleteUserAction}><input type="hidden" name="id" value={uu.id} /><button className="btn-ghost text-xs text-red-600">削除</button></form>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody></table>
        </div>
        <div className="mt-4 border-t border-line pt-3">
          <p className="mb-2 text-sm font-medium">ユーザーを追加</p>
          <ActionForm action={addUserAction} className="flex flex-wrap items-end gap-2">
            <Field label="メールアドレス"><input name="email" type="email" className="input" placeholder="person@example.com" autoComplete="off" /></Field>
            <Field label="仮パスワード（8文字以上）"><input name="password" type="text" className="input" autoComplete="off" /></Field>
            <button className="btn">追加</button>
          </ActionForm>
          <p className="mt-2 text-xs text-muted">追加後、本人がこの仮パスワードでログイン → パスワード変更＆2段階認証を各自で登録してください。</p>
        </div>
      </Card>
      <Card title="2段階認証（2FA）">
        <p className="mb-3 text-sm text-muted">
          ログインにパスワードに加えて認証アプリ（Google Authenticator、1Password など）の6桁コードを求めます。{user ? <>対象：<b>{user.email}</b></> : null}
        </p>
        {totpState === 'done' && <p className="mb-3 text-sm text-green-600">2段階認証を有効にしました。次回ログインからコードが必要です。</p>}
        {totpState === 'off' && <p className="mb-3 text-sm text-green-600">2段階認証を無効にしました。</p>}
        {totpState === 'bad' && <p className="mb-3 text-sm text-red-600">コードが違います。もう一度お試しください。</p>}
        {totp.enabled ? (
          <div className="space-y-3">
            <p className="text-sm"><span className="rounded bg-green-600 px-2 py-0.5 text-xs text-white">有効</span></p>
            <form action={disableTotp2fa} className="flex flex-wrap items-end gap-2">
              <label className="text-sm">
                <span className="mb-1 block text-muted">無効にするには現在の6桁コード</span>
                <input name="code" inputMode="numeric" autoComplete="one-time-code" className="input w-40 font-mono" placeholder="123456" required />
              </label>
              <button className="btn-ghost text-red-600">2段階認証を無効にする</button>
            </form>
          </div>
        ) : qrSvg ? (
          <div className="space-y-3">
            <p className="text-sm">認証アプリで下のQRコードを読み取り、表示された6桁コードを入力してください。</p>
            <div className="inline-block rounded bg-white p-2" dangerouslySetInnerHTML={{ __html: qrSvg }} />
            <p className="text-xs text-muted">QRが読めない場合の手動キー：<code className="break-all font-mono">{totp.secret}</code></p>
            <form action={confirmTotp} className="flex flex-wrap items-end gap-2">
              <label className="text-sm">
                <span className="mb-1 block text-muted">認証アプリの6桁コード</span>
                <input name="code" inputMode="numeric" autoComplete="one-time-code" className="input w-40 font-mono" placeholder="123456" required />
              </label>
              <button className="btn">有効にする</button>
            </form>
          </div>
        ) : (
          <form action={startTotp}>
            <button className="btn">2段階認証を設定する</button>
          </form>
        )}
      </Card>
    </div>
    </>
  );
}
