'use server';

import { redirect } from 'next/navigation';
import { headers } from 'next/headers';
import { createAdmin, endSession, hasAdmin, startSession, verifyLogin } from '@/lib/auth';
import { isLimited, rateLimited } from '@/lib/body';
import { safeEqual } from '@/lib/secrets';

export type FormState = { error?: string };

async function ip(): Promise<string> {
  return ((await headers()).get('x-forwarded-for') ?? '').split(',')[0].trim() || 'unknown';
}

export async function login(_: FormState, fd: FormData): Promise<FormState> {
  // only failed attempts count toward the limit
  const key = `login:${await ip()}`;
  if (isLimited(key, 10)) return { error: '試行回数が多すぎます。しばらくしてからやり直してください。' };
  const id = await verifyLogin(String(fd.get('email') ?? ''), String(fd.get('password') ?? ''));
  if (!id) {
    rateLimited(key, 10, 10 * 60_000);
    return { error: 'メールアドレスまたはパスワードが違います。' };
  }
  await startSession(id);
  redirect('/');
}

// First-run setup is guarded by SETUP_TOKEN from the server environment,
// so a freshly deployed instance cannot be claimed by whoever finds it first.
export async function setup(_: FormState, fd: FormData): Promise<FormState> {
  if (await hasAdmin()) redirect('/login');
  if (rateLimited(`setup:${await ip()}`, 10, 10 * 60_000)) return { error: '試行回数が多すぎます。' };
  const expected = process.env.SETUP_TOKEN ?? '';
  if (!expected || !safeEqual(String(fd.get('setupToken') ?? ''), expected)) return { error: 'セットアップトークンが SETUP_TOKEN と一致しません。' };
  const email = String(fd.get('email') ?? '').trim();
  const password = String(fd.get('password') ?? '');
  if (!/^[^@\s]+@[^@\s]+$/.test(email)) return { error: '正しいメールアドレスを入力してください。' };
  if (password.length < 12) return { error: 'パスワードは12文字以上にしてください。' };
  const id = await createAdmin(email, password);
  await startSession(id);
  redirect('/settings');
}

export async function logout(): Promise<void> {
  await endSession();
  redirect('/login');
}
