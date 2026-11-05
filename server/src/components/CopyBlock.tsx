'use client';

import { useState } from 'react';
import { useMask } from '@/components/Mask';
import { pseudo, type MaskKind } from '@/lib/mask';

// Shows a block of text with a one-click copy button (for Claude Code remediation prompts etc.).
// `mask` lists identity tokens embedded in the text (host name, address, path …). During a demo (mask on)
// those are shown as pseudonyms and copy is blocked, because a pseudonymised prompt must never be run.
export function CopyBlock({ text, mask }: { text: string; mask?: { from: string; kind: MaskKind }[] }) {
  const [copied, setCopied] = useState(false);
  const masked = useMask();
  const blocked = masked && !!mask?.length;
  const display = blocked ? mask!.reduce((acc, m) => (m.from ? acc.split(m.from).join(pseudo(m.kind, m.from)) : acc), text) : text;
  const copy = async () => {
    if (blocked) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked (e.g. insecure context): the text is selectable below */
    }
  };
  return (
    <div>
      <div className="mb-2 flex justify-end">
        <button type="button" onClick={copy} disabled={blocked} title={blocked ? 'デモ用マスク中はコピーできません（解除してください）' : undefined} className="btn-ghost text-xs disabled:opacity-50">{copied ? 'コピーしました' : blocked ? '🕶 マスク中（コピー不可）' : 'クリップボードにコピー'}</button>
      </div>
      {blocked && <p className="mb-1 text-[11px] text-muted">🕶 デモ用マスク中：対象ホスト名・接続先・ホストID・パスを擬名に置き換えて表示しています（コピーは解除後）。</p>}
      <pre className="max-h-96 select-all overflow-auto whitespace-pre-wrap break-words rounded bg-bg p-3 text-xs">{display}</pre>
    </div>
  );
}
