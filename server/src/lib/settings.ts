import { q, q1 } from './db';
import { decrypt, encrypt } from './secrets';

export interface MailSettings {
  enabled: boolean;
  host: string;
  port: number;
  secure: boolean; // true = implicit TLS (465); false = STARTTLS (587)
  user: string;
  passwordEnc: string; // encrypted app password
  from: string;
  to: string; // comma separated
}

export interface PolicySettings {
  notifyMinSeverity: 'critical' | 'high' | 'medium' | 'low';
  notifyKev: boolean;
  staleHours: number; // alert when a host has not reported for this long
  fullRematchHour: number; // local hour for the daily re-match of all inventories
  logRetentionDays: number; // raw logs; aggregates are kept forever
  diskGuardPercent: number; // stop storing raw logs above this disk usage
  ignoreIps: string[]; // log rules never alert for these source IPs (monitoring, own servers)
  digestHour: number; // daily summary mail (server time); -1 = off
  osvCacheHours: number;
}

export const DEFAULT_MAIL: MailSettings = {
  enabled: false, host: 'smtp.gmail.com', port: 587, secure: false, user: '', passwordEnc: '', from: '', to: '',
};

export const DEFAULT_POLICY: PolicySettings = {
  notifyMinSeverity: 'critical', notifyKev: true, staleHours: 26, fullRematchHour: 6, logRetentionDays: 30, diskGuardPercent: 90, ignoreIps: [], digestHour: 8, osvCacheHours: 20,
};

export async function getSetting<T>(key: string, fallback: T): Promise<T> {
  const r = await q1<{ value: T }>('SELECT value FROM settings WHERE key=$1', [key]);
  return r ? { ...fallback, ...r.value } : fallback;
}

export async function setSetting(key: string, value: unknown): Promise<void> {
  await q('INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value', [key, JSON.stringify(value)]);
}

export const getMail = () => getSetting<MailSettings>('mail', DEFAULT_MAIL);
export const getPolicy = () => getSetting<PolicySettings>('policy', DEFAULT_POLICY);

export function mailPassword(m: MailSettings): string {
  return m.passwordEnc ? decrypt(m.passwordEnc) : '';
}

export function encryptPassword(p: string): string {
  return encrypt(p);
}
