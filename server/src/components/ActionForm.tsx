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
      {state.ok && <p className="mt-3 text-sm text-green-600">{state.ok}</p>}
      {state.error && <p className="mt-3 text-sm text-red-600">{state.error}</p>}
    </form>
  );
}
