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

export type SevLevel = 'critical' | 'high' | 'medium' | 'low';
export interface PolicySettings {
  // The "対応ライン" — the severity threshold treated as actionable. screenLevel drives what the UI
  // surfaces as 要対応/緊急 (home, findings default, badges, host counts); mailLevel drives what is e-mailed
  // immediately (below it goes to the daily digest). KEV is always treated as top when notifyKev is on.
  screenLevel: SevLevel;
  mailLevel: SevLevel;
  watchAlwaysImmediate: boolean; // watched CVEs e-mail on any event regardless of severity (else: only a
  // published fix is always immediate; a mere detection follows mailLevel)
  notifyKev: boolean;
  staleHours: number; // alert when a host has not reported for this long
  fullRematchHour: number; // local hour for the daily re-match of all inventories
  logRetentionDays: number; // raw logs; aggregates are kept forever
  diskGuardPercent: number; // stop storing raw logs above this disk usage
  ignoreIps: string[]; // log rules never alert for these source IPs (monitoring, own servers)
  digestHour: number; // daily summary mail (server time); -1 = off
  osvCacheHours: number;
  defaultAllowedIps: string[]; // global default allowed source IPs/CIDRs (empty = no restriction)
  // Daily web-traffic analytics: a metric alerts when yesterday >= its floor AND >= webSpikeMult x the
  // trailing 7-day average. webTransferMB flags one IP pulling that many MB in a day; fail2banBanFloor is
  // the lower spike floor used for the fail2ban-ban rule (its volume is low, so the generic 100 is too high).
  webReqFloor: number;
  web4xxFloor: number;
  web5xxFloor: number;
  webSpikeMult: number;
  webTransferMB: number;
  fail2banBanFloor: number;
}

export const DEFAULT_MAIL: MailSettings = {
  enabled: false, host: 'smtp.gmail.com', port: 587, secure: false, user: '', passwordEnc: '', from: '', to: '',
};

export const DEFAULT_POLICY: PolicySettings = {
  screenLevel: 'critical', mailLevel: 'critical', watchAlwaysImmediate: false, notifyKev: true, staleHours: 26, fullRematchHour: 6, logRetentionDays: 30, diskGuardPercent: 90, ignoreIps: [], digestHour: 8, osvCacheHours: 20, defaultAllowedIps: [],
  webReqFloor: 300, web4xxFloor: 300, web5xxFloor: 30, webSpikeMult: 3, webTransferMB: 300, fail2banBanFloor: 20,
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
