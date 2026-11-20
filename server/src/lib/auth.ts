import bcrypt from 'bcryptjs';
import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { q, q1 } from './db';
import { decrypt, encrypt, randomToken, sha256hex } from './secrets';
import { generateSecret } from './totp';

const COOKIE = 'minisoc2_session';
const TTL_DAYS = 14;
let dummyHash: string | undefined;

export interface User {
  id: number;
  email: string;
}

export async function hasAdmin(): Promise<boolean> {
  return !!(await q1('SELECT 1 FROM admin_users LIMIT 1'));
}

export async function createAdmin(email: string, password: string): Promise<number> {
  const hash = await bcrypt.hash(password, 12);
  const r = await q1<{ id: number }>('INSERT INTO admin_users(email, password_hash) VALUES ($1,$2) RETURNING id', [email.toLowerCase(), hash]);
  return r!.id;
}

// --- Multi-user management (every user is a full admin) ---
export interface UserRow { id: number; email: string; totp_enabled: boolean; created_at: Date; last_login_at: Date | null }

export async function listUsers(): Promise<UserRow[]> {
  return q<UserRow>('SELECT id, email, totp_enabled, created_at, last_login_at FROM admin_users ORDER BY id');
}

// Add a user with a temporary password they change after first login. Returns an error string on failure.
export async function addUser(email: string, password: string): Promise<{ ok?: true; error?: string }> {
  const e = email.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) return { error: '正しいメールアドレスを入力してください。' };
  if (password.length < 8) return { error: 'パスワードは8文字以上にしてください。' };
  if (await q1('SELECT 1 FROM admin_users WHERE email=$1', [e])) return { error: 'そのメールアドレスは既に登録されています。' };
  await createAdmin(e, password);
  return { ok: true };
}

export async function countUsers(): Promise<number> {
  return Number((await q1<{ n: string }>('SELECT count(*) AS n FROM admin_users'))?.n ?? 0);
}

export async function deleteUser(id: number): Promise<void> {
  await q('DELETE FROM admin_users WHERE id=$1', [id]); // sessions cascade
}

export async function resetUserPassword(id: number, password: string): Promise<{ ok?: true; error?: string }> {
  if (password.length < 8) return { error: 'パスワードは8文字以上にしてください。' };
  const hash = await bcrypt.hash(password, 12);
  await q('UPDATE admin_users SET password_hash=$2 WHERE id=$1', [id, hash]);
  await q('DELETE FROM sessions WHERE user_id=$1', [id]); // force re-login with the new password
  return { ok: true };
}

export interface LoginResult {
  id: number;
  totpEnabled: boolean;
  totpSecret: string; // decrypted; only used in-process to verify the second factor at login
}

export async function verifyLogin(email: string, password: string): Promise<LoginResult | null> {
  const u = await q1<{ id: number; password_hash: string; totp_enabled: boolean; totp_secret: string }>(
    'SELECT id, password_hash, totp_enabled, totp_secret FROM admin_users WHERE email=$1', [email.toLowerCase()]);
  if (!u) {
    await bcrypt.compare(password, (dummyHash ??= await bcrypt.hash('not-a-password', 12))); // equalize timing
    return null;
  }
  if (!(await bcrypt.compare(password, u.password_hash))) return null;
  return { id: u.id, totpEnabled: u.totp_enabled, totpSecret: u.totp_secret ? decrypt(u.totp_secret) : '' };
}

// --- TOTP second factor management ---

// Generate a fresh (not yet enabled) secret for enrollment and store it encrypted.
export async function startTotpSecret(userId: number): Promise<string> {
  const secret = generateSecret();
  await q('UPDATE admin_users SET totp_secret=$2, totp_enabled=false WHERE id=$1', [userId, encrypt(secret)]);
  return secret;
}

export async function getTotp(userId: number): Promise<{ enabled: boolean; secret: string }> {
  const u = await q1<{ totp_enabled: boolean; totp_secret: string }>('SELECT totp_enabled, totp_secret FROM admin_users WHERE id=$1', [userId]);
  return { enabled: !!u?.totp_enabled, secret: u?.totp_secret ? decrypt(u.totp_secret) : '' };
}

export async function enableTotp(userId: number): Promise<void> {
  await q('UPDATE admin_users SET totp_enabled=true WHERE id=$1', [userId]);
}

export async function disableTotp(userId: number): Promise<void> {
  await q("UPDATE admin_users SET totp_enabled=false, totp_secret='' WHERE id=$1", [userId]);
}

export async function startSession(userId: number): Promise<void> {
  const token = randomToken();
  await q("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES ($1,$2, now() + ($3 || ' days')::interval)", [sha256hex(token), userId, String(TTL_DAYS)]);
  await q('UPDATE admin_users SET last_login_at=now() WHERE id=$1', [userId]);
  await q('DELETE FROM sessions WHERE expires_at < now()');
  (await cookies()).set(COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: TTL_DAYS * 86400,
  });
}

export async function endSession(): Promise<void> {
  const jar = await cookies();
  const t = jar.get(COOKIE)?.value;
  if (t) await q('DELETE FROM sessions WHERE token_hash=$1', [sha256hex(t)]);
  jar.delete(COOKIE);
}

export async function currentUser(): Promise<User | null> {
  const t = (await cookies()).get(COOKIE)?.value;
  if (!t) return null;
  return q1<User>('SELECT u.id, u.email FROM sessions s JOIN admin_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at > now()', [sha256hex(t)]);
}

// Keep only a safe same-site path (leading single slash, not a protocol-relative "//", not the auth pages)
// so a ?next= value can never become an open redirect to another origin.
export function safeNext(raw: string | null | undefined): string {
  if (!raw || !raw.startsWith('/') || raw.startsWith('//')) return '';
  if (raw.startsWith('/login') || raw.startsWith('/setup')) return '';
  return raw;
}

export async function requireUser(): Promise<User> {
  const u = await currentUser();
  if (!u) {
    if (!(await hasAdmin())) redirect('/setup');
    const next = safeNext((await headers()).get('x-pathname'));
    redirect(next ? `/login?next=${encodeURIComponent(next)}` : '/login');
  }
  return u;
}
