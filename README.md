# minisoc2

> minisoc2 is the next generation of minisoc: an AI-era defense system for **Linux servers only** (Amazon Linux 2023, Ubuntu, and other RPM/dpkg/apk distros). On top of SBOM/CVE/log monitoring it adds server-side AIDE-style file-integrity detection, Sigma log threat detection, pull-type (read-only SSH) registration for agent-less hosts, admin TOTP 2FA, per-host allowed-IP lists, a real-time control channel for on-demand collection, a per-host patch-history timeline, and copy-paste Claude Code remediation prompts. Every host is accessed read-only; the server never writes to a host or runs commands on it. Windows/macOS are out of scope.

## Overview
minisoc2 is a lightweight, self-hosted SOC (security operations center) for a handful to a few hundred Linux servers. Every host is accessed **read-only** — the server can never push commands or writes to a host.

- **Agent** (`agent/`): a single dependency-free Node.js file. A scheduler (cron) runs it; it collects installed packages, pending OS security updates and host state, reports to the server and exits. Nothing stays resident unless you enable the optional control channel (see below), and even then the server can only ask the host to collect — never to run arbitrary commands.
- **Server** (`server/`): Next.js + PostgreSQL web console and API, plus a worker that syncs vulnerability feeds, matches every host's inventory, hosts the real-time control channel, and emails alerts.

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
- **Pull-type hosts (read-only SSH)**: for hosts that cannot run the agent (e.g. shared hosting / Sakura rental server) — lockfile SBOM, runtime versions, ports and daily logs over SSH, no root required, no writes.
- **Projects**: evaluation runs only on registered projects; the agent's auto-detected directories are shown as candidates to approve. Sub-directories can be excluded, and non-deployed work copies (`outputs/`, backup dirs) are skipped so stale backups don't produce false findings.
- **Per-project remediation**: findings are shown with the versions actually installed under that project (no cross-project version mixing), and the suggested upgrade target stays on the installed version's own major release line (never a cross-major downgrade).
- **Patch history**: each host has a "patch record" timeline of resolved vulnerabilities in the order they were observed, with before → after versions, the kind of fix (updated / removed / excluded) and a running count — so improvements visibly accumulate.
- **Allowed-IP lists** per host (and a global default), **TOTP 2FA** for the console, and **copy-paste Claude Code remediation prompts** per fix.

### On-demand collection and the real-time control channel
Normally the agent reports on its schedule (hourly) and a lightweight check-in (every 5 minutes) lets the console request a one-off collection, so after you apply a fix it shows as resolved within a few minutes.

For near-instant feedback you can also run the agent as a resident service, `minisoc2-agent wait`: it holds one **outbound** WebSocket to the server (NAT-friendly; no inbound port). The server then pushes on-demand collections in seconds, and the console shows the host as online. The channel carries a fixed set of verbs only (`collect` / `rematch` / `update`) — the agent still only ever collects read-only, so there is no remote-exec surface. The cron schedule stays in place as the reliable fallback if the channel is down.

The console's "confirm fix / collect now" button uses this: after you remediate, press it and the page refreshes automatically once a fresh report lands.

### Agent updates
Each run fetches `<server>/agent/manifest.json`. If a newer build is listed, it is downloaded, its sha256 and **ed25519 signature** are checked against the public key embedded in the running agent, and then it runs. If anything fails, the newest build already on disk runs instead. You can pin a version (`minisoc2-agent config --pin <version>`) or turn updates off (`--auto-update off`).

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
npm run start      # web console + API on port 3042
npm run worker     # background jobs + control-channel hub (run as a second service)
```

Run both `npm run start` and `npm run worker` under systemd (or another supervisor). Put the reverse proxy in front of port 3042.

If you use ModSecurity with the OWASP CRS, exclude `/api/v1/enroll`, `/api/v1/report`, `/api/v1/logs` and `/api/v1/ws` from body inspection. The agent sends gzip bodies with `Content-Encoding: gzip`, which CRS rule 920450 blocks. Also, the console's Server Actions POST their RPC as `text/plain` with a `Next-Action` header, which CRS content-type rules reject — allow requests that carry that header, e.g.:

```apache
SecRule REQUEST_HEADERS:Next-Action "@rx ." "id:1000503,phase:1,nolog,pass,ctl:ruleRemoveById=920420,ctl:ruleRemoveById=920450,ctl:ruleRemoveById=920470"
```

To enable the optional real-time control channel, the worker opens a WebSocket hub on `127.0.0.1:3043` (override with `AGENT_WS_PORT`). Proxy `/api/v1/ws` to it as a WebSocket upgrade **before** the catch-all proxy, e.g. with Apache's `mod_proxy_wstunnel`:

```apache
ProxyPass        /api/v1/ws ws://127.0.0.1:3043/
ProxyPassReverse /api/v1/ws ws://127.0.0.1:3043/
ProxyPass        /          http://127.0.0.1:3042/
ProxyPassReverse /          http://127.0.0.1:3042/
```

Vercel and other serverless hosts are not supported: the worker must run continuously and PostgreSQL is required.

## Usage
1. Open `https://<your-server>/setup` and create the administrator. You need the `SETUP_TOKEN` from `.env`.
2. **Settings**: turn on email. For Gmail, use an app password: Google Account → Security → 2-Step Verification → App passwords. Then send a test mail.
3. **Add host**: create an enroll token and run the command shown on the target host, for example:
   ```bash
   sudo npx -y https://<your-server>/agent/minisoc2-agent.tgz install \
     --server https://<your-server> --token <enroll-token> --scan /srv,/var/www,/home
   ```
   This registers the host, copies the agent to `~/.minisoc2/`, schedules an hourly run plus a 5-minute check-in, and sends the first report.
   For hosts that cannot run the agent (shared hosting), use **Hosts → Add pull host (SSH)** instead: the server collects over read-only SSH.
4. (Optional) For near-instant on-demand collection, run the control channel as a service on the host:
   ```ini
   # /etc/systemd/system/minisoc2-agent-wait.service
   [Service]
   ExecStart=/usr/bin/node /root/.minisoc2/minisoc2.mjs wait
   Restart=always
   RestartSec=10
   ```
   `systemctl enable --now minisoc2-agent-wait.service`. The host then shows as online and collects within seconds when you press "collect now".
5. Review **Vulnerabilities**, **Alerts** and **Hosts**. Each host has a **patch record** of what has been fixed. Add CVEs you must track to **Watched CVEs**.

Agent commands:

```
minisoc2-agent run [--no-update] [--dry-run]
minisoc2-agent checkin                                       # cheap poll; collects only if requested
minisoc2-agent wait                                          # resident control channel (real-time on-demand collect)
minisoc2-agent send-log --source <name> [--file <path>]     # or pipe lines on stdin
minisoc2-agent config [--scan <dir,dir>] [--skip <name,name>] [--auto-update on|off] [--pin <version>|--unpin]
                     [--log-files <path,glob>] [--journal on|off] [--sudo on|off]
                     [--aide on|off] [--aide-paths <dir,dir>] [--aide-excludes <dir,dir>]
minisoc2-agent schedule install|remove|show [--every <hours>]
```

## Notes
- Run the agent as root to read system-wide files. Without root, unreadable items are skipped and reported as collection errors. Alternatively run it as a user with passwordless sudo and set `config --sudo on`; logs are then read through `sudo -n`.
- Only exact pins (`==`) in `requirements.txt` can be matched. Ranges are skipped.
- Keep the signing private key off the hosts. Replacing it (`npm run keygen -- --force`) makes existing agents reject new builds until they are reinstalled.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

---

# minisoc2（日本語）

> minisoc2 は minisoc の次世代版で、**Linux サーバー専用**（Amazon Linux 2023・Ubuntu、その他 RPM/dpkg/apk 系）の、AI 時代の防御システムです。SBOM／CVE／ログ監視に加え、サーバー側 AIDE 相当のファイル改ざん検知、Sigma によるログ脅威検知、エージェントを置けないホスト向けのプル型（読み取り専用 SSH）登録、管理者の TOTP 2FA、ホストごとの許可 IP、オンデマンド収集のためのリアルタイム制御チャネル、ホストごとの「対処の記録（パッチ適用履歴）」、コピペで使える Claude Code 修復プロンプトを備えます。ホストへのアクセスは必ず読み取り専用で、サーバーからホストへ書き込みや命令は行いません。Windows / macOS は対象外です。

## 概要
minisoc2 は、数台〜数百台の Linux サーバーを見守る軽量なセルフホスト型 SOC（セキュリティ監視センター）です。ホストへのアクセスは必ず**読み取り専用**で、サーバーからホストへ命令や書き込みを送る経路はありません。

- **エージェント**（`agent/`）：依存ゼロの Node.js 単一ファイル。cron（スケジューラ）から起動され、インストール済みパッケージ・OS の未適用セキュリティ更新・ホストの状態を集めてサーバーへ送り、終了します。常駐するのは任意の制御チャネルを有効にしたときだけで、その場合もサーバーができるのは「収集して」と頼むことだけ（任意コマンドの実行経路はありません）。
- **サーバー**（`server/`）：Next.js + PostgreSQL の管理画面と API に加え、脆弱性フィードの同期・全ホストの照合・リアルタイム制御チャネル・メール通知を行うワーカーで構成されます。

現在検知できるもの：

| 対象 | 情報源 |
|---|---|
| アプリ依存の脆弱性（npm の `package-lock.json`、PyPI の `requirements*.txt` の固定版、Packagist の `composer.lock`） | [OSV.dev](https://osv.dev) |
| Debian / Ubuntu / Alpine のパッケージ | OSV.dev |
| RPM 系（Amazon Linux・RHEL 系）の未適用セキュリティ更新 | ホスト自身の `dnf updateinfo`（AL2023 では `--releasever=latest`） |
| 悪用が確認された脆弱性 | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| 報告が途絶えたホスト・古くなった脆弱性フィード | サーバー自身 |
| 新しい待受ポート、新規ログインアカウント、`authorized_keys`／`sudoers`／`passwd`／cron の変更 | エージェントのホスト状態 |
| 監視中の CVE（出現時と修正到達時に通知） | サーバー自身 |

ホストの初回報告は基準線になります（まとめメール1通）。以降は新しく見つかったものだけを通知します。「影響なし」と判断した項目は CycloneDX VEX の理由付きで抑止でき、判断が記録として残ります。

**ログ監視**：各実行で journald とログファイル（`/var/log/secure`、`auth.log`、fail2ban、Apache/nginx のアクセスログ。設定可能）の新着を差分送信し、アプリからは `minisoc2-agent send-log` でいつでも行を送れます。新しい IP からの SSH ログイン、ブルートフォース、sudo 失敗、新規ユーザーの sudo、アカウント作成、200 応答した機微な Web パス、404 スキャンの多発、監査キーなどをルールで通知し、日次で「直近7日平均の3倍」の急増源を検出します。生ログは設定期間（既定30日・日次パーティション）保持し、ディスク使用率が閾値を超えると保存を停止します（日次集計は恒久保持）。

AI 防御機能（実装済み）：
- **ファイル改ざん検知（AIDE 相当）**：エージェントが監視対象のシステムパスを読み取り専用でハッシュ化。基準線はサーバー側で自動確定し、SSH 鍵・sudoers・passwd/shadow・バイナリ・cron・systemd ユニットの変更を通知します。
- **ログ脅威検知（Sigma）**：SigmaHQ の Linux ルールを同期・行マッチャにコンパイルし、内蔵の高シグナルルールと併用します。
- **プル型ホスト（読み取り専用 SSH）**：エージェントを動かせないホスト（共用ホスティング／さくらのレンタルサーバー等）向けに、lockfile の SBOM・実行環境のバージョン・ポート・日次ログを SSH で収集。root 不要・書き込みなし。
- **プロジェクト**：評価は登録済みプロジェクトだけに行い、自動検出したディレクトリは承認候補として提示します。サブディレクトリは除外でき、非デプロイの作業控え（`outputs/` やバックアップ）はスキャン対象外にして、古い控えによる誤検知を防ぎます。
- **プロジェクト単位の修復**：脆弱性は「そのプロジェクト配下に実在するバージョン」で表示し（他プロジェクトのバージョンを混在させない）、修正版の目安は導入版と同じメジャー系列に収めます（別系列へのダウングレードは提案しません）。
- **対処の記録（パッチ適用履歴）**：ホストごとに、解消した脆弱性を観測順のタイムラインで表示します（before → after のバージョン、種別＝更新／削除／除外、累積件数）。改善が目に見えて積み上がります。
- ホストごとの**許可 IP**（と全体の既定）、管理画面の **TOTP 2FA**、修正ごとの**コピペ用 Claude Code 修復プロンプト**。

### オンデマンド収集とリアルタイム制御チャネル
通常はエージェントが定期（毎時）報告し、軽量なチェックイン（5分おき）で画面からの単発収集要求を拾うので、対処後は数分で「解消」に反映されます。

さらに即時性が欲しい場合は、エージェントを常駐サービス `minisoc2-agent wait` として動かせます。サーバーへ**外向き**の WebSocket を1本張り続け（NAT 越え不要・inbound なし）、サーバーは数秒でオンデマンド収集を push、画面にはオンライン表示が出ます。チャネルで送れるのは固定の動詞（`collect` / `rematch` / `update`）だけで、エージェントは依然として読み取り専用の収集しか行わないため、任意コマンド実行の面はありません。cron のスケジュールは、チャネル不通時の確実なフォールバックとして併存します。

画面の「対処を確認（今すぐ収集）」ボタンがこれを使います。対処後に押すと、新しい報告が届き次第ページが自動更新されます。

### エージェントの更新
各実行で `<server>/agent/manifest.json` を確認します。新しい版があればダウンロードし、sha256 と **ed25519 署名**を実行中エージェントに埋め込まれた公開鍵で検証してから実行します。どこかで失敗した場合は、ディスク上の最新版で動きます。版の固定（`minisoc2-agent config --pin <version>`）や更新の停止（`--auto-update off`）が可能です。

minisoc2 サーバーには到達できるが npm やインターネットには出られないホストでも、エージェントは minisoc2 サーバーが配信するため同じように動きます。サーバーに到達できないホストは対象外です。

## インストール

要件：Node.js 20.9+、PostgreSQL 14+、TLS 付きリバースプロキシ（Apache や nginx 等）。

```bash
git clone https://github.com/daishir0/minisoc2.git
cd minisoc2
npm install                 # エージェントのビルドツール
(cd server && npm install)

# 1. データベース
sudo -u postgres psql -c "CREATE USER minisoc2 WITH PASSWORD 'secret';" -c "CREATE DATABASE minisoc2 OWNER minisoc2;"

# 2. 設定
cp server/.env.example server/.env    # すべての値を編集
npm run keygen                       # エージェントの署名用 ed25519 鍵ペア
npm run agent:release                # エージェントをビルド・署名して server/data/agent へ

# 3. サーバー
cd server
npm run migrate
npm run build
npm run start      # 管理画面 + API（ポート 3042）
npm run worker     # バックグラウンドジョブ + 制御チャネルのハブ（別サービスとして常駐）
```

`npm run start` と `npm run worker` の両方を systemd（等のスーパーバイザ）で常駐させ、リバースプロキシをポート 3042 の前段に置きます。

ModSecurity + OWASP CRS を使う場合は、`/api/v1/enroll`・`/api/v1/report`・`/api/v1/logs`・`/api/v1/ws` をボディ検査から除外してください（エージェントは `Content-Encoding: gzip` の本文を送るため、CRS ルール 920450 が阻害します）。また、管理画面の Server Actions は RPC を `text/plain`＋`Next-Action` ヘッダで POST するため CRS のコンテンツタイプ系ルールに弾かれます。次のように当ヘッダを持つリクエストを許可してください：

```apache
SecRule REQUEST_HEADERS:Next-Action "@rx ." "id:1000503,phase:1,nolog,pass,ctl:ruleRemoveById=920420,ctl:ruleRemoveById=920450,ctl:ruleRemoveById=920470"
```

任意のリアルタイム制御チャネルを有効にする場合、ワーカーは WebSocket ハブを `127.0.0.1:3043`（`AGENT_WS_PORT` で変更可）で開きます。`/api/v1/ws` を、全体のプロキシより**前**に WebSocket アップグレードとしてプロキシしてください（Apache の `mod_proxy_wstunnel` 例）：

```apache
ProxyPass        /api/v1/ws ws://127.0.0.1:3043/
ProxyPassReverse /api/v1/ws ws://127.0.0.1:3043/
ProxyPass        /          http://127.0.0.1:3042/
ProxyPassReverse /          http://127.0.0.1:3042/
```

Vercel 等のサーバーレスは非対応です（ワーカーの常駐と PostgreSQL が必須）。

## 使い方
1. `https://<your-server>/setup` を開き、管理者を作成します（`.env` の `SETUP_TOKEN` が必要）。
2. **設定**：メールを有効化します。Gmail はアプリパスワード（Google アカウント → セキュリティ → 2段階認証 → アプリパスワード）を使い、テスト送信します。
3. **ホスト追加**：登録トークンを作り、対象ホストで表示されたコマンドを実行します。例：
   ```bash
   sudo npx -y https://<your-server>/agent/minisoc2-agent.tgz install \
     --server https://<your-server> --token <enroll-token> --scan /srv,/var/www,/home
   ```
   ホストを登録し、エージェントを `~/.minisoc2/` にコピーし、毎時実行と5分おきのチェックインを設定し、初回報告を送ります。
   エージェントを動かせないホスト（共用ホスティング）は、代わりに **ホスト → プル型を追加（SSH）** を使います（サーバーが読み取り専用 SSH で収集）。
4. （任意）即時のオンデマンド収集が欲しい場合は、ホストで制御チャネルを常駐サービスにします：
   ```ini
   # /etc/systemd/system/minisoc2-agent-wait.service
   [Service]
   ExecStart=/usr/bin/node /root/.minisoc2/minisoc2.mjs wait
   Restart=always
   RestartSec=10
   ```
   `systemctl enable --now minisoc2-agent-wait.service`。以降、画面にオンライン表示が出て、「今すぐ収集」で数秒で反映されます。
5. **脆弱性**・**アラート**・**ホスト**を確認します。各ホストには「**対処の記録**」があり、何を直したかが時系列で残ります。必ず追う CVE は **監視中の CVE** に登録します。

エージェントのコマンド：

```
minisoc2-agent run [--no-update] [--dry-run]
minisoc2-agent checkin                                       # 軽量ポーリング。要求時のみ収集
minisoc2-agent wait                                          # 常駐の制御チャネル（リアルタイムのオンデマンド収集）
minisoc2-agent send-log --source <name> [--file <path>]     # または標準入力で行を渡す
minisoc2-agent config [--scan <dir,dir>] [--skip <name,name>] [--auto-update on|off] [--pin <version>|--unpin]
                     [--log-files <path,glob>] [--journal on|off] [--sudo on|off]
                     [--aide on|off] [--aide-paths <dir,dir>] [--aide-excludes <dir,dir>]
minisoc2-agent schedule install|remove|show [--every <hours>]
```

## 注意
- システム全体のファイルを読むにはエージェントを root で実行します。root でない場合、読めない項目はスキップされ収集エラーとして報告されます。あるいはパスワード不要 sudo のユーザーで実行し `config --sudo on` を設定すると、ログは `sudo -n` 経由で読みます。
- `requirements.txt` は厳密な固定（`==`）のみ照合できます。範囲指定はスキップします。
- 署名用の秘密鍵はホストに置かないでください。鍵を差し替える（`npm run keygen -- --force`）と、既存エージェントは再インストールするまで新しいビルドを拒否します。

## ライセンス
本プロジェクトは MIT ライセンスです。詳細は LICENSE ファイルを参照してください。
