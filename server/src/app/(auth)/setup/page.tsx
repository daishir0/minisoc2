export const dynamic = 'force-dynamic';

import { redirect } from 'next/navigation';
import { hasAdmin } from '@/lib/auth';
import { setup } from '../actions';
import { AuthForm } from '../AuthForm';

export default async function SetupPage() {
  if (await hasAdmin()) redirect('/login');
  return (
    <>
      <p className="mb-4 text-sm text-muted">管理者アカウントを作成します。セットアップトークンは、サーバーの .env にある SETUP_TOKEN の値です。</p>
      <AuthForm
        action={setup}
        submit="管理者を作成"
        fields={[
          { name: 'setupToken', label: 'セットアップトークン', type: 'password' },
          { name: 'email', label: 'メールアドレス', type: 'email' },
          { name: 'password', label: 'パスワード（12文字以上）', type: 'password' },
        ]}
      />
    </>
  );
}
