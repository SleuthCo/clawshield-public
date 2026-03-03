# ClawShield Installation Guide

Complete step-by-step guide for setting up ClawShield + OpenClaw from scratch.

## Prerequisites

The setup wizard checks these automatically (Step 0), but here's what you need and where to get each one.

### 1. Git

**What**: Version control. Needed if installing OpenClaw from the SleuthCo fork.

| Platform | Install |
|----------|---------|
| Windows | `winget install Git.Git` |
| Linux | `sudo apt install -y git` |
| macOS | `brew install git` |

Download: https://git-scm.com/downloads

### 2. Node.js (v22+)

**What**: JavaScript runtime. OpenClaw is a Node.js application.

| Platform | Install |
|----------|---------|
| Windows | `winget install OpenJS.NodeJS.LTS` |
| Linux | `sudo apt install -y nodejs` (or use [nvm](https://github.com/nvm-sh/nvm)) |
| macOS | `brew install node@22` |

Download: https://nodejs.org/en/download/

**Verify**: `node --version` should show `v22.x.x` or higher.

> npm ships with Node.js — no separate install needed.

### 3. pnpm

**What**: Fast package manager. Required for building OpenClaw from source (fork install).

| Platform | Install |
|----------|---------|
| All | `npm install -g pnpm` |

**Verify**: `pnpm --version`

### 4. Go (v1.24+)

**What**: Go compiler. ClawShield proxy and audit binaries are written in Go.

| Platform | Install |
|----------|---------|
| Windows | `winget install GoLang.Go` |
| Linux | `sudo apt install -y golang` (or download from go.dev) |
| macOS | `brew install go` |

Download: https://go.dev/dl/

**Verify**: `go version` should show `go1.24.x` or higher.

### 5. GCC (C compiler)

**What**: C compiler. Required by CGO for SQLite support in the audit database.

| Platform | Install |
|----------|---------|
| Windows | `winget install BrechtSanders.WinLibs.POSIX.UCRT` |
| Linux | `sudo apt install -y build-essential` |
| macOS | `xcode-select --install` |

Download (Windows): https://winlibs.com/

**Windows note**: After WinLibs installs via winget, `gcc.exe` may not be in PATH. The wizard scans common WinGet package locations automatically. If it still can't find GCC, add the `mingw64/bin/` directory to your PATH manually.

**Verify**: `gcc --version`

---

## Required Information

The wizard asks for these in Steps 1-7. Gather them beforehand to avoid interruptions.

### Step 1: Your Information

| Field | Example | Where to get it |
|-------|---------|-----------------|
| Display name | `Your Name` | Your name as you want it to appear in agent interactions |
| Email | `you@example.com` | Your email address |

### Step 2: Installation Directories

| Field | Default (Windows) | Default (Linux) |
|-------|-------------------|-----------------|
| OpenClaw config dir | `~/.openclaw` | `~/.openclaw` |
| ClawShield data dir | `~/.clawshield` | `/etc/clawshield` |

If installing from the SleuthCo fork, you'll also need:
- **Fork path**: Local clone of https://github.com/SleuthCo/openclaw (default: `~/openclaw`)

### Step 3: Anthropic API Key

**What**: API key for Claude models. This is the only required secret.

**How to get it**:
1. Go to https://console.anthropic.com/
2. Sign in or create an account
3. Navigate to **API Keys** in the left sidebar
4. Click **Create Key**
5. Copy the key (starts with `sk-ant-`)

**Cost**: Pay-per-use. See https://www.anthropic.com/pricing for current rates.

**Environment variable**: You can also set `ANTHROPIC_API_KEY` before running the wizard and it will auto-detect it.

### Step 4: Agents

| Field | Default | Notes |
|-------|---------|-------|
| Agent names | `apple,banana,cherry,orange,pineapple` | Comma-separated list of agent personas |
| Default model | `anthropic/claude-sonnet-4-5` | Any Anthropic model ID |

**Optional — LM Studio (local inference)**:
If you want to run models locally alongside Claude:
1. Download LM Studio from https://lmstudio.ai/
2. Start a local server (default: `http://localhost:1234/v1`)
3. Load a model (e.g., `qwen_qwen3-next-80b-a3b-instruct`)
4. The wizard will ask for the URL and model ID

### Step 5: Slack Integration (optional)

**What**: Lets agents interact in Slack channels.

**How to create a Slack app**:
1. Go to https://api.slack.com/apps
2. Click **Create New App** > **From scratch**
3. Name it (e.g., "ClawShield Agents"), pick your workspace
4. Under **OAuth & Permissions**, add these **Bot Token Scopes**:
   - `chat:write` — send messages
   - `app_mentions:read` — respond to @mentions
   - `channels:read` — see channel list
   - `channels:history` — read channel messages
   - `im:read` — read DMs
   - `im:history` — read DM history
   - `im:write` — send DMs
5. Under **Socket Mode**, enable it
6. Create an **App-Level Token** with scope `connections:write` — this gives you the `xapp-...` token
7. Under **Install App**, install to your workspace
8. Copy the **Bot User OAuth Token** (`xoxb-...`) from the OAuth & Permissions page
9. Under **Event Subscriptions**, enable events and subscribe to:
   - `message.channels`
   - `message.im`
   - `app_mention`

**Tokens needed by the wizard**:
| Token | Prefix | Where |
|-------|--------|-------|
| Bot token | `xoxb-` | OAuth & Permissions > Bot User OAuth Token |
| App token | `xapp-` | Basic Information > App-Level Tokens |

**Environment variables**: `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`

### Step 6: Telegram Integration (optional)

**What**: Lets agents interact in Telegram chats.

**How to create a Telegram bot**:
1. Open Telegram and message [@BotFather](https://t.me/BotFather)
2. Send `/newbot`
3. Choose a name (e.g., "Friday Agent")
4. Choose a username (must end in `bot`, e.g., `friday_agent_bot`)
5. BotFather gives you a token like `1234567890:ABCdefGHIjklmNOPqrsTUVwxyz`
6. Copy this token

**Per-agent bots** (optional): You can create a separate Telegram bot for each agent. The wizard will ask for each agent's token individually. Agents without a dedicated bot use the default token.

**Environment variable**: `TELEGRAM_BOT_TOKEN` (for the default bot)

### Step 7: Security Policy

| Field | Default | Notes |
|-------|---------|-------|
| Policy | Auto-generated | Default enables all 3 scanners (vuln, prompt injection, malware) |
| Gateway port | `18790` | Internal, loopback only. OpenClaw gateway listens here. |
| Proxy port | `18789` | Public-facing. ClawShield proxy listens here. |

If you have an existing policy YAML, provide its path. Otherwise the wizard generates a comprehensive default.

---

## Running the Wizard

### Quick start

```bash
# Clone the repo
git clone https://github.com/SleuthCo/clawshield
cd clawshield

# Build the setup wizard
go build ./proxy/cmd/clawshield-setup/

# Run it
./clawshield-setup        # Linux/macOS
clawshield-setup.exe      # Windows
```

### What happens

1. **Step 0**: Checks all 6 dependencies, offers to auto-install missing ones
2. **Steps 1-7**: Collects your information, API keys, channel tokens, policy config
3. **Step 8**: Installs OpenClaw, builds ClawShield binaries, writes config files and start scripts

### Resume after failure

The wizard saves progress after each step to `~/.clawshield/.setup-state.json`. If the wizard fails or you kill it mid-way:

```bash
# Just re-run — it detects saved progress and asks to resume
./clawshield-setup
```

State expires after 24 hours. Secrets are base64-encoded (not encrypted — treat the state file as sensitive).

### Non-interactive mode (Docker/CI)

```bash
clawshield-setup \
  --non-interactive \
  --anthropic-key "$ANTHROPIC_API_KEY" \
  --display-name "CI Bot" \
  --email "ci@example.com" \
  --agents "apple,cherry" \
  --with-slack \
  --slack-bot-token "$SLACK_BOT_TOKEN" \
  --slack-app-token "$SLACK_APP_TOKEN"
```

### Install from SleuthCo fork (security patches)

```bash
# Clone the fork first
git clone https://github.com/SleuthCo/openclaw ~/openclaw

# Run wizard with --from-fork
clawshield-setup --from-fork --fork-path ~/openclaw
```

This includes security patches:
- #13777 — redact secrets in CLI config output
- #13779 — Aliyun/Qwen developer role mapping fix
- #13780 — trust binding agentId (prevents multi-agent misdirection)

---

## After Installation

### Start ClawShield

**Windows** (use the generated start script):
```
%USERPROFILE%\.clawshield\clawshield-start.bat
```

**PowerShell**:
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.clawshield\clawshield-start.ps1"
```

**Linux** (systemd):
```bash
sudo systemctl daemon-reload
sudo systemctl start clawshield-gateway clawshield-proxy
sudo systemctl enable clawshield-gateway clawshield-proxy
```

**Manual** (two terminals):
```bash
# Terminal 1: OpenClaw gateway
cd ~/.openclaw && ANTHROPIC_API_KEY=sk-ant-... openclaw gateway

# Terminal 2: ClawShield proxy
~/.clawshield/bin/clawshield-proxy \
  --policy ~/.clawshield/policy.yaml \
  --gateway-url http://127.0.0.1:18790 \
  --gateway-token <your-token> \
  --listen :18789
```

### Build the Control UI (web dashboard)

The OpenClaw gateway serves a web dashboard at `http://localhost:18790`, but the UI assets must be built first. If you skip this step, the gateway runs fine but shows "Control UI assets not found" and the dashboard returns a text error instead of the UI.

```bash
# From the OpenClaw repo (fork or npm-installed source)
cd ~/openclaw    # or wherever your OpenClaw source is
npm run ui:build
```

This builds the Vite SPA into `dist/control-ui/`. The gateway detects UI assets **once at startup** and caches the result — so if you build the UI after starting the gateway, you must **restart the gateway** for it to pick up the new assets.

**Important**: The gateway caches whether UI assets exist at startup. If it starts without them, it will keep returning "assets not found" even after you build them. Always build the UI *before* starting the gateway, or restart after building.

**If installed from fork** (`npm install -g .`): The global npm package is symlinked to your local repo, so `npm run ui:build` in the repo puts assets where the gateway expects them automatically.

**Dashboard auth**: If your gateway has token auth enabled (default), the dashboard will show "unauthorized: gateway token missing" on first load. Go to the **Overview** tab and paste your gateway token into the **Token** field. Your token is in `~/.openclaw/openclaw.json` under `gateway.auth.token`.

### Verify it's working

```bash
# Check proxy is listening
curl http://127.0.0.1:18789/health

# Check gateway is running
curl http://127.0.0.1:18790/health

# Check Control UI is serving (should return HTML, not an error message)
curl -s http://127.0.0.1:18790/ | head -1
# Expected: <!doctype html>
```

### Generated files

| File | Purpose |
|------|---------|
| `~/.openclaw/openclaw.json` | Full OpenClaw config (agents, bindings, channels, models) |
| `~/.openclaw/.env` | Anthropic API key |
| `~/.openclaw/agents/*/` | Agent directories (knowledge, sessions, vectorstore) |
| `~/.clawshield/policy.yaml` | Security policy (tool allowlist, scanners, domain allowlist) |
| `~/.clawshield/bin/clawshield-proxy` | Proxy binary |
| `~/.clawshield/bin/clawshield-audit` | Audit query tool |
| `~/.clawshield/clawshield-start.bat` | Windows start script |
| `~/.clawshield/clawshield-start.ps1` | PowerShell start script |

---

## Troubleshooting

### "pnpm not found" after installing Node.js

Close and reopen your terminal, then run `npm install -g pnpm`.

### GCC not found on Windows

WinLibs installs GCC deep in `AppData`. The wizard tries to find it automatically. If it fails:
1. Open File Explorer
2. Navigate to `%LOCALAPPDATA%\Microsoft\WinGet\Packages\`
3. Find the `BrechtSanders.WinLibs.POSIX.UCRT_*` folder
4. Add its `mingw64\bin\` directory to your PATH

### "clawshield-proxy not recognized" when running start script

This means the wizard couldn't build the proxy binary (GCC was likely missing). Fix:
1. Install GCC (see Prerequisites above)
2. Re-run the wizard — it will resume from where it left off and build the binary

### Control UI shows "assets not found" or blank page

The gateway caches UI asset detection at startup. If it started before the UI was built:

1. Build the UI: `cd ~/openclaw && npm run ui:build`
2. Verify `dist/control-ui/index.html` exists
3. **Restart the gateway** — it won't detect new assets without a restart

If you see "unauthorized: gateway token missing" in the dashboard, go to the **Overview** tab (not Chat) and paste your token from `~/.openclaw/openclaw.json` → `gateway.auth.token`.

### WSL bash interferes with pnpm

On Windows, if pnpm's `script-shell` is set to `/bin/bash` (WSL), builds fail with `execvpe(/bin/bash) failed`. The wizard auto-fixes this by pointing pnpm to Git Bash instead. Manual fix:

```bash
pnpm config set script-shell "C:\Program Files\Git\bin\bash.exe"
```

## eBPF Monitor (Layer 3)

The eBPF monitor is now a Go binary (replacing the previous Python/BCC implementation).

### Requirements

**Full eBPF mode:**
- Linux kernel 5.0+
- BTF support (`/sys/kernel/btf/vmlinux` must exist)
- Root or `CAP_BPF` capability

**Fallback procfs mode:**
- Any Linux system with `/proc` filesystem
- No special capabilities required

### Running

```bash
# Build
go build -o clawshield-ebpf ./ebpf/cmd/clawshield-ebpf/

# Run (auto-detects best backend)
./clawshield-ebpf
```

The monitor automatically detects system capabilities and falls back to procfs polling if eBPF is unavailable.
