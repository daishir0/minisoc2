// Log detection rules. Each line from a host is tested against every rule whose source matches.
//   threshold:  alert when `count` hits for the same (host, rule, group) fall within `windowMin`
//   firstSeen:  alert when the group value was never seen on that host before (after the first batch)
//   neither:    every hit alerts (rate limited to one alert per host/rule/group per hour)
// Rules with alert=false only record hits and daily counts (used for statistics and spike checks).

export interface LogRule {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source?: RegExp;
  pattern: RegExp; // named group "g" is the grouping value (IP, user ...)
  test?: (m: RegExpExecArray, line: string) => boolean;
  threshold?: { count: number; windowMin: number };
  firstSeen?: string; // log_seen.kind
  alert?: boolean;
}

const IP = String.raw`(?<g>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}:[0-9a-fA-F:]{2,38})`; // IPv4 or IPv6 (must contain ':')
const ACCESS = /(?:access_log|access\.log)$/;
// matched against the path without its query string
const SENSITIVE_PATH = /\/\.env(?:\.\w+)?$|\/\.git\/|\/\.svn\/|\/\.aws\/|\/\.ssh\/|wp-config\.php|\/phpinfo\.php$|id_rsa|\.(?:sql|sql\.gz|bak|old)$|\/server-status|\/actuator\/(?:env|heapdump)|\/etc\/passwd/i;

export const RULES: LogRule[] = [
  {
    id: 'ssh_accept_new_ip',
    title: 'SSHログイン成功（初めて見るIPのときだけ通知）',
    severity: 'critical',
    pattern: new RegExp(String.raw`sshd.*Accepted \S+ for \S+ from ${IP}`),
    firstSeen: 'ssh_ip',
  },
  {
    id: 'ssh_bruteforce',
    title: 'SSHのログイン失敗が集中（総当たりの疑い）',
    severity: 'medium',
    pattern: new RegExp(String.raw`sshd.*(?:Failed password|Invalid user|authentication failure|Connection closed by invalid user).*?(?:from |rhost=|invalid user \S+ )${IP}`),
    threshold: { count: 20, windowMin: 10 },
  },
  {
    id: 'sudo_auth_failure',
    title: 'sudo の認証失敗・権限外の実行',
    severity: 'medium',
    pattern: /sudo.*(?:authentication failure|incorrect password attempt|NOT in sudoers|user NOT authorized)/,
  },
  {
    id: 'sudo_new_user',
    title: 'sudo の実行（初めて見るユーザーのときだけ通知）',
    severity: 'medium',
    pattern: /sudo(?:\[\d+\])?:\s+(?<g>[\w.-]+) : .*COMMAND=/,
    firstSeen: 'sudo_user',
  },
  {
    id: 'account_created',
    title: 'アカウントが作成されました',
    severity: 'critical',
    pattern: /(?:useradd|adduser)(?:\[\d+\])?:.*new user: name=(?<g>[^,\s]+)/,
  },
  {
    id: 'account_password_changed',
    title: 'アカウントのパスワードが変更されました',
    severity: 'medium',
    pattern: /(?:passwd|chpasswd)(?:\[\d+\])?:.*password changed for (?<g>\S+)/,
  },
  {
    id: 'web_sensitive_200',
    title: 'Web：機微なパスに 200 応答（情報漏えいの疑い）',
    severity: 'critical',
    source: ACCESS,
    pattern: new RegExp(String.raw`^${IP} \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) (?<path>\S+) [^"]*" 200 (?<bytes>\d+)`),
    test: (m) => Number(m.groups?.bytes ?? 0) > 0 && SENSITIVE_PATH.test((m.groups?.path ?? '').split('?')[0]),
  },
  {
    id: 'web_scan_burst',
    title: 'Web：同じIPから大量の 404（スキャンの疑い）',
    severity: 'medium',
    source: ACCESS,
    pattern: new RegExp(String.raw`^${IP} \S+ \S+ \[[^\]]+\] "[^"]*" 404 `),
    threshold: { count: 300, windowMin: 10 },
  },
  {
    id: 'fail2ban_ban',
    title: 'fail2ban が遮断',
    severity: 'info',
    pattern: new RegExp(String.raw`fail2ban\.actions.*\bBan ${IP}`),
    alert: false,
  },
  {
    id: 'auditd_watch',
    title: 'auditd の監視キーに一致する変更',
    severity: 'medium',
    pattern: /type=SYSCALL.* key="?(?<g>soc_[a-z_]+|minisoc2_[a-z_]+)"?/,
  },
  {
    id: 'kernel_segfault',
    title: 'プロセスの異常終了（segfault）',
    severity: 'low',
    pattern: /kernel:.*\b(?<g>\S+)\[\d+\]: segfault at/,
    alert: false,
  },
];

export interface Hit {
  rule: LogRule;
  grp: string;
  ts: Date;
  sample: string;
}

export function matchLine(source: string, message: string, ts: Date): Hit[] {
  const hits: Hit[] = [];
  for (const rule of RULES) {
    if (rule.source && !rule.source.test(source)) continue;
    const m = rule.pattern.exec(message);
    if (!m) continue;
    if (rule.test && !rule.test(m, message)) continue;
    hits.push({ rule, grp: (m.groups?.g ?? '').slice(0, 200), ts, sample: message.slice(0, 1000) });
  }
  return hits;
}
