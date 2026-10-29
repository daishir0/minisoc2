'use client';

import { useFormStatus } from 'react-dom';

// A submit button that shows a spinner and disables itself while its parent <form>'s server action
// is running (e.g. a pull-host SSH re-scan that takes 10-20s), so a click gives immediate feedback.
export function PendingButton({ children, pendingText, className = 'btn' }: { children: React.ReactNode; pendingText?: string; className?: string }) {
  const { pending } = useFormStatus();
  return (
    <button className={className} disabled={pending} aria-busy={pending}>
      {pending ? (
        <span className="inline-flex items-center gap-1.5">
          <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
          </svg>
          {pendingText ?? '処理中…'}
        </span>
      ) : children}
    </button>
  );
}
