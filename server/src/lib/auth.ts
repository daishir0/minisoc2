import bcrypt from 'bcryptjs';
import { cookies } from 'next/headers';
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

export async function requireUser(): Promise<User> {
  const u = await currentUser();
  if (!u) redirect((await hasAdmin()) ? '/login' : '/setup');
  return u;
}
