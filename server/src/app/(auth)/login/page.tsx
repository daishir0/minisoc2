export const dynamic = 'force-dynamic';

import { redirect } from 'next/navigation';
import { currentUser, hasAdmin, safeNext } from '@/lib/auth';
import { login } from '../actions';
import { AuthForm } from '../AuthForm';

export default async function LoginPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const next = safeNext((await searchParams).next);
  if (!(await hasAdmin())) redirect('/setup');
  if (await currentUser()) redirect(next || '/');
  return <AuthForm action={login} submit="ログイン" hidden={next ? { next } : undefined} fields={[
    { name: 'email', label: 'メールアドレス', type: 'email' },
    { name: 'password', label: 'パスワード', type: 'password' },
    { name: 'code', label: '認証コード（2段階認証）', optional: true, inputMode: 'numeric', hint: '2段階認証を設定している場合のみ、認証アプリの6桁コードを入力してください。' },
  ]} />;
}
