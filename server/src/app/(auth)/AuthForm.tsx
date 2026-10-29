'use client';

import { useActionState } from 'react';
import type { FormState } from './actions';

export function AuthForm({ action, fields, submit }: {
  action: (s: FormState, fd: FormData) => Promise<FormState>;
  fields: { name: string; label: string; type?: string; optional?: boolean; hint?: string; inputMode?: 'numeric' }[];
  submit: string;
}) {
  const [state, formAction, pending] = useActionState(action, {});
  return (
    <form action={formAction} className="space-y-3">
      {fields.map((f) => (
        <label key={f.name} className="block text-sm">
          <span className="mb-1 block text-muted">{f.label}</span>
          <input className="input" name={f.name} type={f.type ?? 'text'} required={!f.optional} inputMode={f.inputMode}
            autoCapitalize="none" autoCorrect="off" spellCheck={false}
            autoComplete={f.type === 'password' ? (submit === 'ログイン' ? 'current-password' : 'new-password') : f.type === 'email' ? 'username' : 'one-time-code'} />
          {f.hint && <span className="mt-1 block text-xs text-muted">{f.hint}</span>}
        </label>
      ))}
      {state.error && <p className="text-sm text-red-600">{state.error}</p>}
      <button className="btn w-full" disabled={pending}>{submit}</button>
    </form>
  );
}
