'use client';

import { useActionState } from 'react';
import { createEnrollToken, type Result } from '../actions';

export function EnrollForm({ publicUrl }: { publicUrl: string }) {
  const [state, action, pending] = useActionState<Result, FormData>(createEnrollToken, {});
  const npx = state.token ? `npx -y ${publicUrl}/agent/minisoc2-agent.tgz install --server ${publicUrl} --token ${state.token} --scan /srv,/var/www,/home` : '';
  const offline = state.token ? `node minisoc2-agent.mjs install --server ${publicUrl} --token ${state.token} --scan /srv,/var/www,/home` : '';
  return (
    <>
      <form action={action} className="flex flex-wrap items-end gap-3 text-sm">
        <label><span className="mb-1 block text-muted">ラベル</span><input name="label" className="input w-48" placeholder="Webサーバー群" /></label>
        <label><span className="mb-1 block text-muted">有効期間（時間）</span><input name="hours" type="number" defaultValue={24} min={1} className="input w-28" /></label>
        <label><span className="mb-1 block text-muted">登録できる台数</span><input name="uses" type="number" defaultValue={1} min={1} className="input w-24" /></label>
        <button className="btn" disabled={pending}>登録トークンを作成</button>
      </form>
      {state.token && (
        <div className="mt-4 space-y-3 text-sm">
          <p className="text-orange-600">今すぐコピーしてください。トークンはこの1回しか表示されません。</p>
          <div>
            <div className="mb-1 font-semibold">インストール（Linux、Node.js 18以上）</div>
            <pre className="whitespace-pre-wrap break-all rounded bg-bg p-3 text-xs select-all">{npx}</pre>
          </div>
          <div>
            <div className="mb-1 font-semibold">npm に接続できないホスト</div>
            <p className="text-muted"><a className="text-accent" href={`${publicUrl}/agent/minisoc2-agent.tgz`}>minisoc2-agent.tgz</a> または <a className="text-accent" href={`${publicUrl}/agent/minisoc2-agent.mjs`}>minisoc2-agent.mjs</a>（単一ファイル）をダウンロードしてホストへコピーし、<code>npx -y ./minisoc2-agent.tgz install …</code> か、次のコマンドを実行します。</p>
            <pre className="whitespace-pre-wrap break-all rounded bg-bg p-3 text-xs select-all">{offline}</pre>
          </div>
          <p className="text-muted">システム全体のファイルも対象にするには root（または管理者）で実行してください。<code>--scan</code> は lockfile を探すディレクトリで、あとから <code>minisoc2-agent config --scan …</code> で変更できます。</p>
        </div>
      )}
    </>
  );
}
