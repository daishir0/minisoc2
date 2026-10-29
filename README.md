# minisoc2

> minisoc2 is the next generation of minisoc: an AI-era defense system for **Linux servers only** (Amazon Linux 2023, Ubuntu, and other RPM/dpkg/apk distros). On top of SBOM/CVE/log monitoring it adds server-side AIDE-style file-integrity detection, Sigma log threat detection, pull-type (read-only SSH) registration for agent-less hosts, admin TOTP 2FA, per-host allowed-IP lists, and copy-paste Claude Code remediation prompts. Every host is accessed read-only; the server never writes to a host or runs commands on it. Windows/macOS are out of scope.

## Overview
minisoc2 is a lightweight, self-hosted SOC (security operations center) for a handful to a few hundred Linux servers. Every host is accessed **read-only** â the server can never push commands or writes to a host.

- **Agent** (`agent/`): a single dependency-free Node.js file. A scheduler (cron) runs it; it collects installed packages, pending OS security updates and host state, reports to the server and exits. Nothing stays resident and the server can never send commands to hosts.
- **Server** (`server/`): Next.js + PostgreSQL web console and API, plus a worker that syncs vulnerability feeds, matches every host's inventory, and emails alerts.

What it detects today:

| Area | Source |
|---|---|
| Vulnerable dependencies (npm `package-lock.json`, PyPI `requirements*.txt` pins, Packagist `composer.lock`) | [OSV.dev](https://osv.dev) |
| Debian / Ubuntu / Alpine packages | OSV.dev |
| RPM distros (Amazon Linux, RHEL family): pending security updates | the host's own `dnf updateinfo` (with `--releasever=latest` on Amazon Linux 2023) |
| Actively exploited vulnerabilities | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Hosts that stopped reporting, stale vulnerability feeds | the server itself |
| New listening ports, new login accounts, changed `authorized_keys` / `sudoers` / `passwd` / cron files | agent host state |
| Watched CVEs (alert when they appear and when the fix lands) | the server itself |

The first report from a host sets a baseline (one summary mail). After that, only new findings are alerted. A finding you have judged "not affected" can be suppressed with a CycloneDX VEX justification, so the decision is recorded.

**Log monitoring**: each run also sends new journald entries and log files (`/var/log/secure`, `auth.log`, fail2ban, Apache/nginx access logs; configurable) incrementally, and applications can push lines any time with `minisoc2-agent send-log`. Rules raise alerts for SSH logins from new IPs, brute force, sudo failures, sudo by new users, account creation, sensitive web paths answered with 200, 404 scan bursts and audit keys; a daily check flags sources whose volume is 3x their 7-day average. Raw logs are kept for a configurable period (default 30 days, daily partitions) and stop being stored above a disk usage threshold; daily aggregates are kept forever.

AI-defense features (implemented):
- **File-integrity (AIDE-style)**: the agent hashes watched system paths read-only; the baseline lives on the server and auto-promotes, and changes to SSH keys, sudoers, passwd/shadow, binaries, cron or systemd units raise alerts.
- **Log threat detection (Sigma)**: SigmaHQ Linux rules are synced and compiled to line matchers, run alongside the built-in high-signal rules.
- **Pull-type hosts (read-only SSH)**: for hosts that cannot run the agent (e.g. shared hosting / Sakura rental server) â lockfile SBOM, runtime versions, ports and daily logs over SSH, no root required, no writes.
- **Projects**: evaluation runs only on registered projects; the agent's auto-detected directories are shown as candidates to approve. Sub-directories can be excluded.
- **Allowed-IP lists** per host (and a global default), **TOTP 2FA** for the console, and **copy-paste Claude Code remediation prompts** per fix.

### Agent updates
Each run fetches `<server>/agent/manifest.json`. If a newer build is listed, it is downloaded, its sha256 and **ed25519 signature** are checked against the public key embedded in the running agent, and then it runs. If anything fails, the newest build already on disk runs instead. You can pin a version (`minisoc2-agent config --pin 0.1.0`) or turn updates off (`--auto-update off`).

Hosts that can reach the minisoc2 server but not npm or the internet work the same way, because the agent is served by your minisoc2 server. Hosts that cannot reach the server are out of scope.

## Installation

Requirements: Node.js 20.9+, PostgreSQL 14+, a reverse proxy with TLS (e.g. Apache or nginx).

```bash
git clone https://github.com/daishir0/minisoc2.git
cd minisoc2
npm install                 # build tools for the agent
(cd server && npm install)

# 1. database
sudo -u postgres psql -c "CREATE USER minisoc2 WITH PASSWORD 'secret';" -c "CREATE DATABASE minisoc2 OWNER minisoc2;"

# 2. configuration
cp server/.env.example server/.env    # then edit every value
npm run keygen                       # ed25519 key pair that signs agent builds
npm run agent:release                # build + sign the agent into server/data/agent

# 3. server
cd server
npm run migrate
npm run build
npm run start      # web console + API on port 3032
npm run worker     # background jobs (run as a second service)
```

Run both `npm run start` and `npm run worker` under systemd (or another supervisor). Put the reverse proxy in front of port 3032.

If you use ModSecurity with the OWASP CRS, exclude `/api/v1/enroll`, `/api/v1/report` and `/api/v1/logs` from body inspection. The agent sends gzip bodies with `Content-Encoding: gzip`, which CRS rule 920450 blocks.

Vercel and other serverless hosts are not supported: the worker must run continuously and PostgreSQL is required.

## Usage
1. Open `https://<your-server>/setup` and create the administrator. You need the `SETUP_TOKEN` from `.env`.
2. **Settings**: turn on email. For Gmail, use an app password: Google Account â Security â 2-Step Verification â App passwords. Then send a test mail.
3. **Add host**: create an enroll token and run the command shown on the target host, for example:
   ```bash
   sudo npx -y https://<your-server>/agent/minisoc2-agent.tgz install \
     --server https://<your-server> --token <enroll-token> --scan /srv,/var/www,/home
   ```
   This registers the host, copies the agent to `~/.minisoc2/`, schedules an hourly run, and sends the first report.
   For hosts that cannot run the agent (shared hosting), use **Hosts → Add pull host (SSH)** instead: the server collects over read-only SSH.
4. Review **Vulnerabilities**, **Alerts** and **Hosts**. Add CVEs you must track to **Watched CVEs**.

Agent commands:

```
minisoc2-agent run [--no-update] [--dry-run]
minisoc2-agent send-log --source <name> [--file <path>]     # or pipe lines on stdin
minisoc2-agent config [--scan <dir,dir>] [--skip <name,name>] [--auto-update on|off] [--pin <version>|--unpin]
                     [--log-files <path,glob>] [--journal on|off] [--sudo on|off]
minisoc2-agent schedule install|remove|show [--every <hours>]
```

## Notes
- Run the agent as root to read system-wide files. Without root, unreadable items are skipped and reported as collection errors. Alternatively run it as a user with passwordless sudo and set `config --sudo on`; logs are then read through `sudo -n`.
- Only exact pins (`==`) in `requirements.txt` can be matched. Ranges are skipped.
- Keep the signing private key off the hosts. Replacing it (`npm run keygen -- --force`) makes existing agents reject new builds until they are reinstalled.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

---

# minisoc2

> minisoc2 ã¯ minisoc ã®æ¬¡ä¸ä»£çã§ãAI æä»£ã®é²å¾¡ã·ã¹ãã ã¨ãã¦ **Linux ãµã¼ãã¼å°ç¨**ï¼Amazon Linux 2023ã»Ubuntu ã»ã RPM/dpkg/apk ç³»ï¼ã«ä½ããã¦ãã¾ããSBOM/CVE/ã­ã°ç£è¦ã«å ãããµã¼ãã¼å´ AIDE ç¸å½ã®ãã¡ã¤ã«æ¹ããæ¤ç¥ãSigma ã«ããã­ã°èå¨æ¤ç¥ãã¨ã¼ã¸ã§ã³ããç½®ããªããã¹ãåãã®ãã«åï¼èª­ã¿åãå°ç¨ SSHï¼ç»é²ãç®¡çè TOTP 2FAããã¹ããã¨ã®è¨±å¯ IPãã³ããã§ä½¿ãã Claude Code ä¿®å¾©ãã­ã³ãããåãã¾ãããã¹ãã¸ã®ã¢ã¯ã»ã¹ã¯å¿ãèª­ã¿åãå°ç¨ã§ããµã¼ãã¼ãããã¹ãã¸æ¸ãè¾¼ã¿ãå½ä»¤ã¯è¡ãã¾ãããWindows / macOS ã¯å¯¾è±¡å¤ã§ãã

## æ¦è¦
minisoc2 ã¯ãæ°å°ãæ°ç¾å°ã® Linux ãµã¼ãã¼ãè¦å®ãè»½éãªã»ã«ããã¹ãå SOCï¼ã»ã­ã¥ãªãã£ç£è¦ã»ã³ã¿ã¼ï¼ã§ãããã¹ãã¸ã®ã¢ã¯ã»ã¹ã¯å¿ã**èª­ã¿åãå°ç¨**ã§ããµã¼ãã¼ãããã¹ãã¸å½ä»¤ãæ¸ãè¾¼ã¿ãéãçµè·¯ã¯ããã¾ããã

- **ã¨ã¼ã¸ã§ã³ã**ï¼`agent/`ï¼ï¼ä¾å­ã¼ã­ã® Node.js åä¸ãã¡ã¤ã«ãcron ãã¿ã¹ã¯ã¹ã±ã¸ã¥ã¼ã©ããèµ·åãããã¨ãã¤ã³ã¹ãã¼ã«æ¸ã¿ããã±ã¼ã¸ã»OS ã®æªé©ç¨ã»ã­ã¥ãªãã£æ´æ°ã»ãã¹ãã®ç¶æãéãã¦ãµã¼ãã¼ã¸éããçµäºãã¾ããå¸¸é§ããããµã¼ãã¼ãããã¹ãã¸å½ä»¤ãéãçµè·¯ãããã¾ããã
- **ãµã¼ãã¼**ï¼`server/`ï¼ï¼Next.js + PostgreSQL ã®ç®¡çç»é¢ã¨ API ã«å ããèå¼±æ§ãã£ã¼ãã®åæã»å¨ãã¹ãã®ç§åã»ã¡ã¼ã«éç¥ãè¡ãã¯ã¼ã«ã¼ã§æ§æããã¾ãã

ç¾å¨æ¤ç¥ã§ãããã®ï¼

| å¯¾è±¡ | æå ±æº |
|---|---|
| ã¢ããªä¾å­ã®èå¼±æ§ï¼npm ã® `package-lock.json`ãPyPI ã® `requirements*.txt` ã®åºå®çãPackagist ã® `composer.lock`ï¼ | OSV.dev |
| Debian / Ubuntu / Alpine ã®ããã±ã¼ã¸ | OSV.dev |
| RPM ç³»ï¼Amazon LinuxãRHEL ç³»ï¼ã®æªé©ç¨ã»ã­ã¥ãªãã£æ´æ° | ãã¹ãèªèº«ã® `dnf updateinfo`ï¼Amazon Linux 2023 ã§ã¯ `--releasever=latest` ãä»ä¸ï¼ |
| å®éã«æªç¨ããã¦ããèå¼±æ§ | CISA KEV |
| å ±åãæ­¢ã¾ã£ããã¹ããæ´æ°ãæ­¢ã¾ã£ãèå¼±æ§ãã£ã¼ã | ãµã¼ãã¼èªèº« |
| æ°ããå¾åãã¼ããæ°ããã­ã°ã¤ã³ã¢ã«ã¦ã³ãã`authorized_keys`ã»`sudoers`ã»`passwd`ã»cron ã®å¤æ´ | ã¨ã¼ã¸ã§ã³ããéãããã¹ãç¶æ |
| ç£è¦å¯¾è±¡ã«ç»é²ãã CVEï¼åºç¾æã¨ãä¿®æ­£ãå±ããæã«éç¥ï¼ | ãµã¼ãã¼èªèº« |

ãã¹ãã®ååå ±åã¯åºæºç·ã¨ãã¦æ±ããã¾ã¨ãã®ã¡ã¼ã«ã1éã ãéãã¾ããä»¥éã¯æ°ããè¦ã¤ãã£ããã®ã ããéç¥ãã¾ãããå½±é¿ããªããã¨å¤æ­ããèå¼±æ§ã¯ CycloneDX VEX ã®çç±ãä»ãã¦ææ­¢ã§ãããã®å¤æ­ãè¨é²ã«æ®ãã¾ãã

**ã­ã°ç£è¦**ï¼ã¨ã¼ã¸ã§ã³ãã¯å®è¡ã®ãã³ã« journald ã¨åã­ã°ãã¡ã¤ã«ï¼`/var/log/secure`ã`auth.log`ãfail2banãApache / nginx ã®ã¢ã¯ã»ã¹ã­ã°ãªã©ãå¤æ´å¯ï¼ã®æ°ããåã ããéãã¾ããã¢ããªããã¯ `minisoc2-agent send-log` ã§ãã¤ã§ãéãã¾ããã«ã¼ã«ã§æ¬¡ã®äºè±¡ãã¢ã©ã¼ãã«ãã¾ãã
- åãã¦è¦ãIPããã®SSHã­ã°ã¤ã³
- SSHã®ç·å½ãã
- sudo ã®èªè¨¼å¤±æãåãã¦è¦ãã¦ã¼ã¶ã¼ã«ãã sudo
- ã¢ã«ã¦ã³ãã®ä½æ
- æ©å¾®ãªWebãã¹ã¸ã®200å¿ç­ã404ã®å¤§éçºçï¼ã¹ã­ã£ã³ï¼
- auditd ã®ç£è¦ã­ã¼ã«ä¸è´ããå¤æ´

ãããã¦ãã­ã°éãç´è¿7æ¥å¹³åã®3åãè¶ããã½ã¼ã¹ãæ¯æ¥æ¤åºãã¾ããçã­ã°ã¯æ¥å¥ã«åãã¦ä¿å­ããä¿å­æéï¼æ¢å®30æ¥ï¼ãéããã¨æ¶ãã¾ãããã£ã¹ã¯ä½¿ç¨çãä¸éãè¶ãã¦ããéã¯ä¿å­ãæ­¢ãã¾ããæ¥å¥ã®éè¨å¤ã¯æ°¸ç¶çã«æ®ãã¾ãã

AI é²å¾¡æ©è½ï¼å®è£æ¸ã¿ï¼ï¼
- **ãã¡ã¤ã«æ¹ããæ¤ç¥ï¼AIDEç¸å½ï¼**ï¼ã¨ã¼ã¸ã§ã³ããç£è¦å¯¾è±¡ã®èª­ã¿åãå°ç¨ããã·ã¥ãéãããã¼ã¹ã©ã¤ã³ã¯ãµã¼ãã¼å´ã§èªåææ ¼ãSSHéµã»sudoersã»passwd/shadowã»å®è¡ãã¡ã¤ã«ã»cronã»systemd ã®å¤åãã¢ã©ã¼ãã
- **ã­ã°èå¨æ¤ç¥ï¼Sigmaï¼**ï¼SigmaHQ ã® Linux ã«ã¼ã«ãåæã»ã³ã³ãã¤ã«ããèªä½ã®é«ã·ã°ãã«ã«ã¼ã«ã¨ä½µç¨ã
- **ãã«åãã¹ãï¼èª­ã¿åãå°ç¨ SSHï¼**ï¼ã¨ã¼ã¸ã§ã³ããç½®ããªããã¹ãï¼å±ç¨ã¬ã³ã¿ã«ãµã¼ãã¼ï¼ãããç­ï¼åããlockfile ã® SBOMã»ã©ã³ã¿ã¤ã çã»ãã¼ãã»æ¥æ¬¡ã­ã°ã SSH ã§åéãroot ä¸è¦ã»æ¸ãè¾¼ã¿ãªãã
- **ãã­ã¸ã§ã¯ã**ï¼è©ä¾¡ã¯ç»é²æ¸ã¿ãã­ã¸ã§ã¯ãã®ã¿ãã¨ã¼ã¸ã§ã³ããèªåæ¤åºãããã£ã¬ã¯ããªã¯åè£ã¨ãã¦æ¿èªç»é²ããµããã£ã¬ã¯ããªã®é¤å¤ãå¯è½ã
- ãã¹ããã¨ã®**è¨±å¯IP**ï¼ï¼å¨ä½æ¢å®ï¼ãç®¡çç»é¢ã® **TOTP 2FA**ãä¿®å¾©ãã¨ã® **Claude Code ãã­ã³ããï¼ã³ããå®è¡ï¼**ã

### ã¨ã¼ã¸ã§ã³ãã®æ´æ°
ã¨ã¼ã¸ã§ã³ãã¯èµ·åã®ãã³ã« `<server>/agent/manifest.json` ãç¢ºèªãã¾ããæ°ããçãããã°ãã¦ã³ã­ã¼ãããsha256 ã¨ **ed25519 ç½²å**ããå®è¡ä¸­ã®ã¨ã¼ã¸ã§ã³ãã«åãè¾¼ã¾ããå¬ééµã§æ¤è¨¼ãã¦ããå®è¡ãã¾ããã©ããã§å¤±æããå ´åã¯ãæåã«ããææ°ã®çã§åãã¾ããçã®åºå®ï¼`minisoc2-agent config --pin 0.1.0`ï¼ããæ´æ°ã®åæ­¢ï¼`--auto-update off`ï¼ãã§ãã¾ãã

npm ãã¤ã³ã¿ã¼ãããã«ã¯åºãããªãã minisoc2 ãµã¼ãã¼ã«ã¯å±ããããã¯ã¼ã¯ã§ããã¨ã¼ã¸ã§ã³ãã®éå¸åãèªåã® minisoc2 ãµã¼ãã¼ãªã®ã§åãããã«åãã¾ããminisoc2 ãµã¼ãã¼ã«å±ããªããã¹ãã¯å¯¾è±¡å¤ã§ãã

## ã¤ã³ã¹ãã¼ã«æ¹æ³

å¿è¦ãªãã®ï¼Node.js 20.9 ä»¥ä¸ãPostgreSQL 14 ä»¥ä¸ãTLS ä»ãã®ãªãã¼ã¹ãã­ã­ã·ï¼Apache ã nginx ãªã©ï¼ã

```bash
git clone https://github.com/daishir0/minisoc2.git
cd minisoc2
npm install
(cd server && npm install)

sudo -u postgres psql -c "CREATE USER minisoc2 WITH PASSWORD 'secret';" -c "CREATE DATABASE minisoc2 OWNER minisoc2;"

cp server/.env.example server/.env    # ãã¹ã¦ã®å¤ãæ¸ãæãã
npm run keygen                       # ã¨ã¼ã¸ã§ã³ãç½²åç¨ã® ed25519 éµãä½æ
npm run agent:release                # ã¨ã¼ã¸ã§ã³ãããã«ãã»ç½²åãã¦ server/data/agent ã«éç½®

cd server
npm run migrate
npm run build
npm run start      # ç®¡çç»é¢ã¨ APIï¼ãã¼ã 3032ï¼
npm run worker     # ããã¯ã°ã©ã¦ã³ãå¦çï¼å¥ãµã¼ãã¹ã¨ãã¦èµ·åï¼
```

`npm run start` ã¨ `npm run worker` ã¯ãã©ã¡ãã systemd ãªã©ã®ã¹ã¼ãã¼ãã¤ã¶ã§å¸¸é§ããããã¼ã 3032 ã®åã«ãªãã¼ã¹ãã­ã­ã·ãç½®ãã¦ãã ããã

ModSecurity ã¨ OWASP CRS ãä½¿ã£ã¦ããå ´åã¯ã`/api/v1/enroll`ã»`/api/v1/report`ã»`/api/v1/logs` ãããã£æ¤æ»ã®å¯¾è±¡ããå¤ãã¦ãã ãããã¨ã¼ã¸ã§ã³ãã¯ `Content-Encoding: gzip` ã§éä¿¡ãããããCRS ã®ã«ã¼ã« 920450 ã«æ­¢ãããã¾ãã

ã¯ã¼ã«ã¼ã®å¸¸é§ã¨ PostgreSQL ãå¿è¦ãªãããVercel ãªã©ã®ãµã¼ãã¼ã¬ã¹ç°å¢ã«ã¯å¯¾å¿ãã¦ãã¾ããã

## ä½¿ãæ¹
1. `https://<ãµã¼ãã¼>/setup` ãéãã`.env` ã® `SETUP_TOKEN` ãä½¿ã£ã¦ç®¡çèãä½æãã¾ãã
2. **Settings** ã§ã¡ã¼ã«éç¥ãæå¹ã«ãã¾ããGmail ã®å ´åã¯ã¢ããªãã¹ã¯ã¼ããä½¿ãã¾ãï¼Google ã¢ã«ã¦ã³ã â ã»ã­ã¥ãªãã£ â 2 æ®µéèªè¨¼ â ã¢ããªãã¹ã¯ã¼ãï¼ããã¹ãã¡ã¼ã«ã§ç¢ºèªã§ãã¾ãã
3. **Add host** ã§ç»é²ãã¼ã¯ã³ãä½ããè¡¨ç¤ºãããã³ãã³ããå¯¾è±¡ãã¹ãã§å®è¡ãã¾ãããã¹ãã®ç»é²ã`~/.minisoc2/` ã¸ã®ã³ãã¼ã1æéãã¨ã®å®æå®è¡ã®ç»é²ãååå ±åã¾ã§ãä¸åº¦ã«è¡ãã¾ãã
4. **Vulnerabilities**ã»**Alerts**ã»**Hosts** ãç¢ºèªãã¾ããè¿½è·¡ãå¿è¦ãª CVE ã¯ **Watched CVEs** ã«ç»é²ãã¾ãã

## æ³¨æç¹
- ã·ã¹ãã å¨ä½ã®ãã¡ã¤ã«ãèª­ãããã«ãã¨ã¼ã¸ã§ã³ãã¯ rootï¼ã¾ãã¯ç®¡çèï¼ã§å®è¡ãã¦ãã ãããæ¨©éãè¶³ããªãé ç®ã¯é£ã°ããåéã¨ã©ã¼ã¨ãã¦å ±åãã¾ãããã¹ã¯ã¼ããªãã§ sudo ã§ããã¦ã¼ã¶ã¼ã§åããå ´åã¯ã`config --sudo on` ã«ããã¨ã­ã°ã `sudo -n` çµç±ã§èª­ã¿ã¾ãã
- `requirements.txt` ã¯ `==` ã§åºå®ãããè¡ã ããç§åãã¾ããç¯å²æå®ã®è¡ã¯å¯¾è±¡å¤ã§ãã
- ç½²åç¨ã®ç§å¯éµã¯ç£è¦å¯¾è±¡ã®ãã¹ãã«ç½®ããªãã§ãã ãããéµãä½ãç´ãï¼`npm run keygen -- --force`ï¼ã¨ãæ¢å­ã®ã¨ã¼ã¸ã§ã³ãã¯åã¤ã³ã¹ãã¼ã«ããã¾ã§æ°ããçãåãä»ãã¾ããã

## ã©ã¤ã»ã³ã¹
ãã®ãã­ã¸ã§ã¯ãã¯MITã©ã¤ã»ã³ã¹ã®ä¸ã§ã©ã¤ã»ã³ã¹ããã¦ãã¾ããè©³ç´°ã¯LICENSEãã¡ã¤ã«ãåç§ãã¦ãã ããã
