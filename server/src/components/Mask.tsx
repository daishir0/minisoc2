'use client';
// Client side of demo masking. A context holds the on/off state (initialised from the cookie on the
// server so there is no flash), <Masked> renders the pseudonym when on and the real text when off, and
// <MaskToggle> flips it — instantly (context) and persistently (cookie). See lib/mask.ts for the rules.
import { createContext, useContext, useState, type ReactNode } from 'react';
import { MASK_COOKIE, maskFree, pseudo, type MaskKind } from '@/lib/mask';

const Ctx = createContext<{ masked: boolean; set: (v: boolean) => void }>({ masked: false, set: () => {} });

export function MaskProvider({ initial, children }: { initial: boolean; children: ReactNode }) {
  const [masked, setMasked] = useState(initial);
  const set = (v: boolean) => {
    setMasked(v);
    try { document.cookie = `${MASK_COOKIE}=${v ? '1' : '0'};path=/;max-age=31536000;samesite=lax`; } catch {}
  };
  return <Ctx.Provider value={{ masked, set }}>{children}</Ctx.Provider>;
}

export const useMask = () => useContext(Ctx).masked;
const useMaskCtx = () => useContext(Ctx);

// Wrap any identity-revealing string. `k` is a stable key (e.g. the host id) so the same entity gets the
// same pseudonym everywhere; omit it to key off the text itself. `plain` keeps a null/empty passthrough.
export function Masked({ kind = 'generic', k, children }: { kind?: MaskKind; k?: string | null; children?: string | null }) {
  const masked = useMask();
  const text = children ?? '';
  if (!masked || !text) return <>{text}</>;
  return <>{pseudo(kind, (k ?? text) || text)}</>;
}

// Free-text variant: pseudonymises identities found anywhere in a generated sentence (titles, details).
export function MaskFree({ children }: { children?: string | null }) {
  const masked = useMask();
  const text = children ?? '';
  if (!masked || !text) return <>{text}</>;
  return <>{maskFree(text)}</>;
}

export function MaskToggle() {
  const { masked, set } = useMaskCtx();
  return (
    <button
      type="button"
      onClick={() => set(!masked)}
      aria-pressed={masked}
      title="デモ用マスク：ホスト名・IP・パス・メールなどを擬名に置き換えます（画面共有・プレゼン用）"
      className={`btn-ghost whitespace-nowrap text-sm ${masked ? 'bg-accent text-white' : 'text-muted'}`}
    >
      {masked ? '🕶 マスク中' : '🕶 マスク'}
    </button>
  );
}
