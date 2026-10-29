import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { revokeEnrollToken } from '../actions';
import { EnrollForm } from './EnrollForm';

export default async function EnrollPage() {
  const publicUrl = (process.env.PUBLIC_URL ?? '').replace(/\/+$/, '');
  const tokens = await q<{ id: number; label: string; uses: number; max_uses: number; expires_at: Date; created_at: Date }>(
    'SELECT id, label, uses, max_uses, expires_at, created_at FROM enroll_tokens WHERE expires_at > now() AND uses < max_uses ORDER BY created_at DESC',
  );
  return (
    <>
      <Card title="ホストを追加">
        <p className="mb-4 text-sm text-muted">
          エージェントは cron やタスクスケジューラから定期的に起動され、パッケージ・OSの未適用セキュリティ更新・ホストの状態を集めてここへ報告し、終了します。
          起動のたびにこのサーバーから署名付きの最新版を取得し、取得できなければ手元の版で動きます。
        </p>
        <EnrollForm publicUrl={publicUrl} />
      </Card>
      <Card title="有効な登録トークン">
        {tokens.length === 0 ? <p className="text-sm text-muted">ありません。</p> : (
          <table className="tbl"><thead><tr><th>ラベル</th><th>使用</th><th>有効期限</th><th>作成</th><th></th></tr></thead><tbody>
            {tokens.map((t) => (
              <tr key={t.id}>
                <td>{t.label || '-'}</td><td>{t.uses}/{t.max_uses}</td><td>{new Date(t.expires_at).toISOString().slice(0, 16).replace('T', ' ')}</td><td>{ago(t.created_at)}</td>
                <td><form action={revokeEnrollToken.bind(null, t.id)}><button className="text-xs text-accent">取り消す</button></form></td>
              </tr>
            ))}
          </tbody></table>
        )}
      </Card>
    </>
  );
}
