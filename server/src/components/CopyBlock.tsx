'use client';

import { useState } from 'react';

// Shows a block of text with a one-click copy button (for Claude Code remediation prompts etc.).
export function CopyBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
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
        <button type="button" onClick={copy} className="btn-ghost text-xs">{copied ? 'コピーしました' : 'クリップボードにコピー'}</button>
      </div>
      <pre className="max-h-96 select-all overflow-auto whitespace-pre-wrap break-words rounded bg-bg p-3 text-xs">{text}</pre>
    </div>
  );
}
