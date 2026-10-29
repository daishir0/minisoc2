# minisoc2

> **Status: under active development.** minisoc2 is the next generation of minisoc, rebuilt as an AI-era defense system for **Linux servers only** (Amazon Linux 2023, Ubuntu, and other RPM/dpkg/apk distros). Headline features being added on top of the inherited SBOM/CVE/log baseline: server-side AIDE-style file-integrity detection, Sigma log threat detection, pull-type (read-only SSH) host registration for agent-less hosts, TOTP 2FA, per-host allowed-IP lists, and copy-paste Claude Code remediation prompts. Windows/macOS are out of scope.

## Overview
minisoc2 is a lightweight, self-hosted SOC (security operations center) for a handful to a few hundred Linux servers. Every host is accessed **read-only** — the server can never push commands or writes to a host.

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

Roadmap (AI-defense features being added): server-side AIDE-style file-integrity detection with auto-promoted baselines, Sigma log threat detection, pull-type read-only SSH collection for agent-less hosts (e.g. shared hosting), TOTP 2FA for the console, per-host allowed-IP lists, and per-remediation Claude Code prompts you can copy and run on the host.

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
2. **Settings**: turn on email. For Gmail, use an app password: Google Account → Security → 2-Step Verification → App passwords. Then send a test mail.
3. **Add host**: create an enroll token and run the command shown on the target host, for example:
   ```bash
   sudo npx -y https://<your-server>/agent/minisoc2-agent.tgz install \
     --server https://<your-server> --token <enroll-token> --scan /srv,/var/www,/home
   ```
   This registers the host, copies the agent to `~/.minisoc2/`, schedules an hourly run, and sends the first report.
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

> **状態：開発中。** minisoc2 は minisoc の次世代版で、AI 時代の防御システムとして **Linux サーバー専用**（Amazon Linux 2023・Ubuntu ほか RPM/dpkg/apk 系）に作り直しています。継承した SBOM/CVE/ログ監視の土台に、サーバー側 AIDE 相当のファイル改ざん検知、Sigma によるログ脅威検知、エージェントを置けないホスト向けのプル型（読み取り専用 SSH）登録、TOTP 2FA、ホストごとの許可 IP、コピペで使える Claude Code 修復プロンプトを追加していきます。Windows / macOS は対象外です。

## 概要
minisoc2 は、数台〜数百台の Linux サーバーを見守る軽量なセルフホスト型 SOC（セキュリティ監視センター）です。ホストへのアクセスは必ず**読み取り専用**で、サーバーからホストへ命令や書き込みを送る経路はありません。

- **エージェント**（`agent/`）：依存ゼロの Node.js 単一ファイル。cron やタスクスケジューラから起動されると、インストール済みパッケージ・OS の未適用セキュリティ更新・ホストの状態を集めてサーバーへ送り、終了します。常駐せず、サーバーからホストへ命令を送る経路もありません。
- **サーバー**（`server/`）：Next.js + PostgreSQL の管理画面と API に加え、脆弱性フィードの同期・全ホストの照合・メール通知を行うワーカーで構成されます。

現在検知できるもの：

| 対象 | 情報源 |
|---|---|
| アプリ依存の脆弱性（npm の `package-lock.json`、PyPI の `requirements*.txt` の固定版、Packagist の `composer.lock`） | OSV.dev |
| Debian / Ubuntu / Alpine のパッケージ | OSV.dev |
| RPM 系（Amazon Linux、RHEL 系）の未適用セキュリティ更新 | ホスト自身の `dnf updateinfo`（Amazon Linux 2023 では `--releasever=latest` を付与） |
| 実際に悪用されている脆弱性 | CISA KEV |
| 報告が止まったホスト、更新が止まった脆弱性フィード | サーバー自身 |
| 新しい待受ポート、新しいログインアカウント、`authorized_keys`・`sudoers`・`passwd`・cron の変更 | エージェントが集めるホスト状態 |
| 監視対象に登録した CVE（出現時と、修正が届いた時に通知） | サーバー自身 |

ホストの初回報告は基準線として扱い、まとめのメールを1通だけ送ります。以降は新しく見つかったものだけを通知します。「影響しない」と判断した脆弱性は CycloneDX VEX の理由を付けて抑止でき、その判断が記録に残ります。

**ログ監視**：エージェントは実行のたびに journald と各ログファイル（`/var/log/secure`、`auth.log`、fail2ban、Apache / nginx のアクセスログなど。変更可）の新しい分だけを送ります。アプリからは `minisoc2-agent send-log` でいつでも送れます。ルールで次の事象をアラートにします。
- 初めて見るIPからのSSHログイン
- SSHの総当たり
- sudo の認証失敗、初めて見るユーザーによる sudo
- アカウントの作成
- 機微なWebパスへの200応答、404の大量発生（スキャン）
- auditd の監視キーに一致する変更

あわせて、ログ量が直近7日平均の3倍を超えたソースを毎日検出します。生ログは日別に分けて保存し、保存期間（既定30日）を過ぎると消します。ディスク使用率が上限を超えている間は保存を止めます。日別の集計値は永続的に残します。

今後追加する AI 防御機能：サーバー側の AIDE 相当のファイル改ざん検知（ベースライン自動昇格）、Sigma によるログ脅威検知、エージェントを置けないホスト（共用レンタルサーバー等）向けのプル型（読み取り専用 SSH）収集、管理画面の TOTP 2FA、ホストごとの許可 IP、修復ごとにコピペして実行できる Claude Code プロンプト。

### エージェントの更新
エージェントは起動のたびに `<server>/agent/manifest.json` を確認します。新しい版があればダウンロードし、sha256 と **ed25519 署名**を、実行中のエージェントに埋め込まれた公開鍵で検証してから実行します。どこかで失敗した場合は、手元にある最新の版で動きます。版の固定（`minisoc2-agent config --pin 0.1.0`）や、更新の停止（`--auto-update off`）もできます。

npm やインターネットには出られないが minisoc2 サーバーには届くネットワークでも、エージェントの配布元が自前の minisoc2 サーバーなので同じように動きます。minisoc2 サーバーに届かないホストは対象外です。

## インストール方法

必要なもの：Node.js 20.9 以上、PostgreSQL 14 以上、TLS 付きのリバースプロキシ（Apache や nginx など）。

```bash
git clone https://github.com/daishir0/minisoc2.git
cd minisoc2
npm install
(cd server && npm install)

sudo -u postgres psql -c "CREATE USER minisoc2 WITH PASSWORD 'secret';" -c "CREATE DATABASE minisoc2 OWNER minisoc2;"

cp server/.env.example server/.env    # すべての値を書き換える
npm run keygen                       # エージェント署名用の ed25519 鍵を作成
npm run agent:release                # エージェントをビルド・署名して server/data/agent に配置

cd server
npm run migrate
npm run build
npm run start      # 管理画面と API（ポート 3032）
npm run worker     # バックグラウンド処理（別サービスとして起動）
```

`npm run start` と `npm run worker` は、どちらも systemd などのスーパーバイザで常駐させ、ポート 3032 の前にリバースプロキシを置いてください。

ModSecurity と OWASP CRS を使っている場合は、`/api/v1/enroll`・`/api/v1/report`・`/api/v1/logs` をボディ検査の対象から外してください。エージェントは `Content-Encoding: gzip` で送信するため、CRS のルール 920450 に止められます。

ワーカーの常駐と PostgreSQL が必要なため、Vercel などのサーバーレス環境には対応していません。

## 使い方
1. `https://<サーバー>/setup` を開き、`.env` の `SETUP_TOKEN` を使って管理者を作成します。
2. **Settings** でメール通知を有効にします。Gmail の場合はアプリパスワードを使います（Google アカウント → セキュリティ → 2 段階認証 → アプリパスワード）。テストメールで確認できます。
3. **Add host** で登録トークンを作り、表示されたコマンドを対象ホストで実行します。ホストの登録、`~/.minisoc2/` へのコピー、1時間ごとの定期実行の登録、初回報告までを一度に行います。
4. **Vulnerabilities**・**Alerts**・**Hosts** を確認します。追跡が必要な CVE は **Watched CVEs** に登録します。

## 注意点
- システム全体のファイルを読むために、エージェントは root（または管理者）で実行してください。権限が足りない項目は飛ばし、収集エラーとして報告します。パスワードなしで sudo できるユーザーで動かす場合は、`config --sudo on` にするとログを `sudo -n` 経由で読みます。
- `requirements.txt` は `==` で固定された行だけを照合します。範囲指定の行は対象外です。
- 署名用の秘密鍵は監視対象のホストに置かないでください。鍵を作り直す（`npm run keygen -- --force`）と、既存のエージェントは再インストールするまで新しい版を受け付けません。

## ライセンス
このプロジェクトはMITライセンスの下でライセンスされています。詳細はLICENSEファイルを参照してください。
