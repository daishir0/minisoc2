export const dynamic = 'force-dynamic';

import { redirect } from 'next/navigation';
import { currentUser, hasAdmin } from '@/lib/auth';
import { login } from '../actions';
import { AuthForm } from '../AuthForm';

export default async function LoginPage() {
  if (!(await hasAdmin())) redirect('/setup');
  if (await currentUser()) redirect('/');
  return <AuthForm action={login} submit="ログイン" fields={[{ name: 'email', label: 'メールアドレス', type: 'email' }, { name: 'password', label: 'パスワード', type: 'password' }]} />;
}
