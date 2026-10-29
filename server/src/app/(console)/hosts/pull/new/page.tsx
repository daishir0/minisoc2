import { ActionForm } from '@/components/ActionForm';
import { Card } from '@/components/ui';
import { addPullHost } from '../../../actions';

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="mb-1 block font-medium">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export default function NewPullHostPage() {
  return (
    <Card title="プル型ホストを登録（読み取り専用SSH）">
      <p className="mb-4 text-sm text-muted">
        エージェントを置けないホスト（さくらのレンタルサーバー等の共用ホスティング）向けです。サーバーが<b>読み取り専用SSH</b>で定期接続し、SBOM（composer.lock など）・ランタイム版（php -v 等）・待受ポート・ログを収集します。root権限が無い環境ではOSパッケージ更新は対象外で、収集もユーザー権限の範囲に限られます。<b>書き込みやsudoは一切行いません。</b>
      </p>
      <ActionForm action={addPullHost} className="grid gap-4 md:grid-cols-2">
        <Field label="表示名"><input name="name" className="input" placeholder="さくら web1" /></Field>
        <Field label="SSHホスト"><input name="sshHost" className="input" placeholder="example.sakura.ne.jp" required /></Field>
        <Field label="SSHユーザー"><input name="sshUser" className="input" required /></Field>
        <Field label="ポート"><input name="sshPort" type="number" className="input" defaultValue={22} /></Field>
        <Field label="認証方式">
          <select name="auth" className="input"><option value="password">パスワード</option><option value="key">秘密鍵</option></select>
        </Field>
        <Field label="パスワード または 秘密鍵（PEM）" hint="暗号化して保存します。秘密鍵はヘッダを含む全文を貼り付けてください。">
          <textarea name="secret" rows={3} className="input font-mono text-xs" required />
        </Field>
        <div className="md:col-span-2">
          <Field label="SBOMを探すディレクトリ（lockfile）" hint="改行またはカンマ区切り。例：~/www、/home/USER/www。この配下の composer.lock / package-lock.json / requirements*.txt を収集します。登録後、評価対象にするにはプロジェクト登録が必要です。">
            <textarea name="scanPaths" rows={2} className="input font-mono text-xs" placeholder="~/www" />
          </Field>
        </div>
        <div className="md:col-span-2">
          <Field label="収集するログファイル" hint="改行またはカンマ区切り。日次ローテーションのファイルも可。例：~/log/*.access_log。前回以降の増加分だけを取り込みます。">
            <textarea name="logGlobs" rows={2} className="input font-mono text-xs" placeholder="~/log/access_log" />
          </Field>
        </div>
        <div className="md:col-span-2"><button className="btn">登録して接続テスト（初回収集）</button></div>
      </ActionForm>
    </Card>
  );
}
