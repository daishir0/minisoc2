import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import QRCode from 'qrcode';
import { ActionForm } from '@/components/ActionForm';
import { Card, SEV_LABEL } from '@/components/ui';
import { currentUser, getTotp } from '@/lib/auth';
import { otpauthURL } from '@/lib/totp';
import { getMail, getPolicy } from '@/lib/settings';
import { confirmTotp, disableTotp2fa, saveMail, savePolicy, startTotp } from '../actions';

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block text-muted">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export default async function SettingsPage({ searchParams }: { searchParams: Promise<{ totp?: string }> }) {
  const mail = await getMail();
  const p = await getPolicy();
  const { totp: totpState } = await searchParams;
  const user = await currentUser();
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
          <Field label="すぐにメールする範囲" hint="KEV・緊急（CVSS 9.0以上）・侵入の兆候・監視の停止が既定です。高以下は画面の詳細でのみ表示します。">
            <select name="notifyMinSeverity" defaultValue={p.notifyMinSeverity} className="input">
              <option value="critical">KEV＋緊急（推奨）</option>
              <option value="high">KEV＋緊急＋{SEV_LABEL.high}</option>
            </select>
          </Field>
          <Field label="日次まとめメールの時刻（時、サーバー時刻）" hint="前日からの変化を1通にまとめて送ります。変化が無い日は送りません。-1 で停止。"><input name="digestHour" type="number" className="input" defaultValue={p.digestHour ?? 8} /></Field>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="notifyKev" defaultChecked={p.notifyKev} /> 悪用が確認された脆弱性（CISA KEV）は深刻度にかかわらずメールする</label>
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
