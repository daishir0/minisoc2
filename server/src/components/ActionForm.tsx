'use client';

import { useActionState } from 'react';
import type { Result } from '@/app/(console)/actions';

// Form bound to a server action returning { ok | error }; shows the outcome inline.
export function ActionForm({ action, children, className }: {
  action: (s: Result, fd: FormData) => Promise<Result>;
  children: React.ReactNode;
  className?: string;
}) {
  const [state, formAction, pending] = useActionState(action, {});
  return (
    <form action={formAction} className={className}>
      <fieldset disabled={pending} className="contents">{children}</fieldset>
      {pending && (
        <p className="mt-3 inline-flex items-center gap-1.5 text-sm text-muted">
          <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
          </svg>
          処理中…
        </p>
      )}
      {state.ok && <p className="mt-3 text-sm text-green-600">{state.ok}</p>}
      {state.error && <p className="mt-3 text-sm text-red-600">{state.error}</p>}
    </form>
  );
}
