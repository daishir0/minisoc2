'use client';

import { useState, useTransition } from 'react';
import { collectAllHosts, rematchAllHosts } from '@/app/(console)/actions';

// Fleet-wide buttons with visible feedback: server actions alone revalidate silently (counts don't
// change for a few seconds), so the click felt dead. Here we show a pending state and a result.
export function FleetOps() {
  const [pending, start] = useTransition();
  const [msg, setMsg] = useState('');
  const [which, setWhich] = useState<'collect' | 'rematch' | null>(null);

  const run = (kind: 'collect' | 'rematch') => {
    setWhich(kind);
    setMsg('');
    start(async () => {
      try {
        const r = kind === 'collect' ? await collectAllHosts() : await rematchAllHosts();
        setMsg(kind === 'collect'
          ? `✅ ${r.n}台に収集を要求しました（接続中は数秒・未接続は次回チェックインで反映）`
          : `✅ ${r.n}台の再照合を予約しました（まもなく反映）`);
      } catch {
        setMsg('⚠ 失敗しました。時間をおいて再度お試しください。');
      } finally {
        setWhich(null);
      }
    });
  };

  const busy = (k: 'collect' | 'rematch') => pending && which === k;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button type="button" onClick={() => run('collect')} disabled={pending} className="btn-ghost disabled:opacity-60" title="全エージェントホストに収集を要求（接続中は即時）">
        {busy('collect') ? '要求中…' : '全ホスト 今すぐ収集'}
      </button>
      <button type="button" onClick={() => run('rematch')} disabled={pending} className="btn-ghost disabled:opacity-60" title="取得済みインベントリで全ホストを再判定（ホストへ接続しません）">
        {busy('rematch') ? '予約中…' : '全ホスト 再照合'}
      </button>
      {msg && <span className="text-xs text-green-600">{msg}</span>}
    </div>
  );
}
