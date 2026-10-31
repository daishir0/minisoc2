'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { requestCollect } from '@/app/(console)/actions';

// "対処を確認" — ask the host to collect now (real time if its control channel is live, otherwise on
// the next check-in), then poll until a fresher report lands and refresh the page so the resolved
// vulnerabilities show up without waiting for the hourly cycle.
export function ConfirmCollect({ hostId, online, lastSeenAt, label = '対処を確認（今すぐ収集）' }: {
  hostId: string; online: boolean; lastSeenAt: string | null; label?: string;
}) {
  const router = useRouter();
  const [state, setState] = useState<'idle' | 'working' | 'done' | 'timeout'>('idle');

  const run = async () => {
    const before = lastSeenAt ? new Date(lastSeenAt).getTime() : 0;
    setState('working');
    try {
      const fd = new FormData();
      fd.set('id', hostId);
      await requestCollect(fd);
    } catch { /* fall through to polling anyway */ }
    const deadline = Date.now() + (online ? 60_000 : 90_000);
    const poll = async () => {
      try {
        const r = await fetch(`/api/host-status?id=${hostId}`, { cache: 'no-store' });
        if (r.ok) {
          const j = (await r.json()) as { lastSeenAt: string | null };
          const seen = j.lastSeenAt ? new Date(j.lastSeenAt).getTime() : 0;
          if (seen > before) { setState('done'); router.refresh(); return; }
        }
      } catch { /* ignore, keep polling */ }
      if (Date.now() < deadline) setTimeout(poll, 3000);
      else setState('timeout');
    };
    setTimeout(poll, 3000);
  };

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={run} disabled={state === 'working'} className="btn disabled:opacity-60">
          {state === 'working' ? '確認中…' : label}
        </button>
        <span className={`inline-flex items-center gap-1 text-xs ${online ? 'text-green-600' : 'text-muted'}`}>
          <span className={`h-2 w-2 rounded-full ${online ? 'bg-green-500' : 'bg-slate-400'}`} />
          {online ? 'オンライン（即時）' : '未接続（次回チェックインで実行）'}
        </span>
      </div>
      {state === 'working' && <p className="text-xs text-muted">{online ? 'ホストに収集を指示しました。数秒で反映されます…' : '収集を要求しました。ホストの次回チェックインを待っています…'}</p>}
      {state === 'done' && <p className="text-xs text-green-600">✅ 最新の報告が届きました。対処結果を反映しました。</p>}
      {state === 'timeout' && <p className="text-xs text-amber-600">まだ新しい報告が届いていません。対処が完了していれば、最大1時間で自動反映されます（この画面は後で再読み込みを）。</p>}
    </div>
  );
}
