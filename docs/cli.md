# PhaseOne10841 CLI & GUI

**Veracity Integrity LLC** · https://VeracityIntegrity.com

Operator command-line interface and local GUI for PhaseOne10841 defensive Agent EDR.

> **DEFENSIVE ONLY** — no exploit PoCs, attack payloads, or offensive tooling.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
- [GUI Usage](#gui-usage)
- [Windows Notes](#windows-notes)
- [Environment Variables](#environment-variables)
- [Safety Notes](#safety-notes)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Node.js 20+
- npm or pnpm
- Docker & Docker Compose (for stack operations)

### Install Dependencies

```bash
cd phaseone-core
npm install
```

### Running the CLI

**Option 1: Via npm script (recommended)**

```bash
npm run phaseone -- help
npm run phaseone -- version
npm run phaseone -- health
```

**Option 2: Via npx**

```bash
npx phaseone help
npx phaseone version
```

**Option 3: npm link (global install)**

```bash
npm link
phaseone help
phaseone version
```

To unlink:

```bash
npm unlink -g phaseone-core
```

### Windows

All CLI commands work on Windows. Use PowerShell or Command Prompt:

```powershell
npm run phaseone -- help
npm run phaseone -- health --json
```

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Onboard (generate .env)
npm run phaseone -- onboard --defaults

# 3. Start Docker stack
npm run phaseone -- compose up

# 4. Check health
npm run phaseone -- health

# 5. Run smoke tests
npm run phaseone -- smoke

# 6. Launch GUI (optional)
npm run phaseone -- gui
```

---

## CLI Commands

### `help`

Show help and available commands.

```bash
phaseone help              # List all commands
phaseone help onboard      # Detailed help for a command
```

### `version`

Show version information.

```bash
phaseone version
```

Output:

```
PhaseOne10841 v0.5.1
CLI v0.5.1
Veracity Integrity LLC
https://VeracityIntegrity.com

Defensive Agent Security Gateway (Agent EDR)
DEFENSIVE ONLY — no exploit tooling
```

### `onboard`

Run interactive onboarding or generate `.env` with defaults.

```bash
# Interactive setup
phaseone onboard

# Non-interactive with defaults (CI-friendly)
phaseone onboard --defaults

# Custom output path
phaseone onboard --defaults --out /tmp/.env

# Force overwrite without backup
phaseone onboard --defaults --force
```

**Options:**

| Flag | Description |
|------|-------------|
| `--defaults, -y` | Non-interactive with default values |
| `--out, -o <path>` | Output path for .env file (default: `.env`) |
| `--force, -f` | Overwrite existing file without backup |

### `health`

Check gateway and dashboard health endpoints.

```bash
phaseone health
phaseone health --json
phaseone health --gateway http://myserver:8080
```

**Options:**

| Flag | Description |
|------|-------------|
| `--gateway <url>` | Gateway URL (default: `http://localhost:8080`) |
| `--dashboard <url>` | Dashboard URL (default: `http://localhost:3000`) |
| `--json` | Output as JSON |

**Example output:**

```
PhaseOne10841 Health Check

✓ gateway_healthz: 200
✓ gateway_readyz: 200
✓ gateway_metrics: 200
✓ dashboard_healthz: 200

All endpoints healthy
Veracity Integrity LLC
```

### `ready`

Check if services are ready (gateway + database).

```bash
phaseone ready
phaseone ready --json
```

**Options:**

| Flag | Description |
|------|-------------|
| `--gateway <url>` | Gateway URL (default: `http://localhost:8080`) |
| `--json` | Output as JSON |

### `metrics`

Fetch Prometheus metrics from gateway.

```bash
phaseone metrics
phaseone metrics --gateway http://myserver:8080
```

### `smoke`

Run post-compose smoke tests.

```bash
phaseone smoke
phaseone smoke --gateway http://myserver:8080 --dashboard http://myserver:3000
```

Checks:
- Gateway healthz/readyz
- Metrics endpoint
- Mock chat completion
- Policy deny (dangerous shell)
- Canary detection
- Phase 5 ops endpoint

### `migrate`

Run database migrations.

```bash
phaseone migrate
```

Applies all SQL migrations from `db/migrations/` to the database specified in `DATABASE_URL`.

### `retention` ⚠️

Run event retention cleanup.

```bash
# Preview what would be deleted (default)
phaseone retention --dry-run
phaseone retention --dry-run --days 14

# Actually delete old data (requires --confirm)
phaseone retention --execute --days 30 --confirm
```

**Options:**

| Flag | Description |
|------|-------------|
| `--dry-run, -n` | Preview what would be deleted (default) |
| `--execute, --apply` | Actually delete old data |
| `--days, -d <n>` | Retention period in days (default: 30) |
| `--confirm` | Required for destructive operations |

**Safety:** This command deletes data. Always run with `--dry-run` first.

### `backup`

Backup Postgres database, policy, and rules.

```bash
phaseone backup
```

Creates a timestamped backup directory under `backups/`:

```
backups/20260916-143000/
├── phaseone-postgres.sql
├── policy/
│   └── default-policy.yaml
├── rules/
│   └── *.yaml
└── MANIFEST.txt
```

**Windows:** Uses PowerShell script (`scripts/backup-windows.ps1`).

### `restore` ⚠️

Restore from a backup directory.

```bash
# Requires --confirm (replaces database contents!)
phaseone restore backups/20260916-143000 --confirm
```

**Safety:** This command **replaces** database contents and overwrites `policy/default-policy.yaml`. Always backup before restoring.

**Windows:** Requires WSL or Git Bash:

```bash
bash scripts/restore.sh backups/20260916-143000
```

### `lab`

Run defensive lab harness (inert fixtures + detectors).

```bash
phaseone lab
```

Returns JSON with:
- Stub counts (email, web, MCP, RAG)
- Fixture counts (benign, injection)
- Monitor results (detection accuracy)

### `permissions`

Analyze tool permissions and capability matrix.

```bash
phaseone permissions
phaseone permissions my-agent-id
```

Reports:
- Capability matrix (filesystem, shell, network, MCP, etc.)
- Excessive agency findings
- Security recommendations

### `compose`

Docker Compose operations.

```bash
phaseone compose up          # Start with --build -d
phaseone compose up gateway  # Start specific service
phaseone compose down --confirm  # Stop (requires confirmation)
phaseone compose ps          # List services
phaseone compose logs        # Show recent logs
phaseone compose logs gateway
phaseone compose restart gateway
```

**Actions:**

| Action | Description |
|--------|-------------|
| `up` | Start services (with `--build -d`) |
| `down` | Stop and remove services ⚠️ |
| `ps` | List running services |
| `logs` | Show last 100 lines of logs |
| `restart` | Restart a specific service |

### `rules`

List detection rules.

```bash
phaseone rules
phaseone rules --json
phaseone rules --dir ./custom-rules
```

**Options:**

| Flag | Description |
|------|-------------|
| `--dir <path>` | Rules directory (default: `./rules`) |
| `--json` | Output as JSON |

**Example output:**

```
PhaseOne10841 Detection Rules
Directory: /path/to/rules

  shell-denied.yaml: Shell command denied (high)
  domain-denied.yaml: Domain access denied (medium)
  injection-blocked.yaml: Prompt injection blocked (high)
  a2a-untrusted.yaml: Untrusted A2A source (medium)
  canary-trigger.yaml: Canary token triggered (critical)
  high-injection-score.yaml: High injection score (high)

6 rule(s) found
```

### `gui`

Launch local GUI for CLI commands.

```bash
phaseone gui                  # Start on port 8888
phaseone gui --port 9000      # Custom port
```

Opens a browser-accessible interface at `http://localhost:8888` (or custom port).

---

## GUI Usage

The GUI provides a graphical interface for all CLI commands.

### Starting the GUI

```bash
npm run phaseone -- gui
# or
npm run phaseone:gui
```

### Features

- **Command List:** All CLI commands in a sidebar
- **Options Form:** Input fields for command options
- **Confirmation Dialogs:** Required for destructive commands
- **Live Output:** Command results displayed in terminal-style output
- **Status Badges:** Visual success/error indicators

### Screenshots

The GUI runs at `http://localhost:8888` by default:

1. Select a command from the sidebar
2. Fill in options (if any)
3. Click "Run Command"
4. View output in the terminal panel

### Safety

- Destructive commands (⚠️) require clicking "Proceed" in a confirmation dialog
- `compose down`, `retention --execute`, and `restore` all prompt before executing

---

## Windows Notes

### PowerShell Execution Policy

If you encounter execution policy errors:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Path Separators

The CLI handles path separators automatically. Use forward slashes (`/`) or backslashes (`\`).

### Docker Desktop

Ensure Docker Desktop is running before using `compose` commands.

### Backup/Restore

- **Backup:** Uses `scripts/backup-windows.ps1` automatically
- **Restore:** Requires WSL or Git Bash

```bash
# In WSL or Git Bash
bash scripts/restore.sh backups/20260916-143000
```

### Scheduled Tasks

To schedule automated backups on Windows:

```powershell
# Run as Administrator
.\scripts\windows\Register-PhaseOneScheduledTasks.ps1
```

Registers daily 2 AM tasks for backup and retention.

---

## Environment Variables

The CLI reads these environment variables (also set via `npm run phaseone -- onboard`):

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEWAY_URL` | Gateway base URL | `http://localhost:8080` |
| `DASHBOARD_URL` | Dashboard base URL | `http://localhost:3000` |
| `DATABASE_URL` | Postgres connection string | `postgres://phaseone:phaseone@localhost:5432/phaseone` |
| `PHASEONE_RULES_DIR` | Detection rules directory | `./rules` |
| `PHASEONE_BACKUP_DIR` | Backup output directory | `./backups` |
| `PHASEONE_RETENTION_DAYS` | Default retention period | `30` |

See `.env.example` for the complete list.

---

## Safety Notes

### Destructive Commands

Commands marked with ⚠️ modify data:

| Command | What it modifies |
|---------|-----------------|
| `retention --execute` | Deletes old events from database |
| `restore` | Replaces database contents |
| `compose down` | Stops and removes containers |

These commands require `--confirm` flag or GUI confirmation.

### Best Practices

1. **Always dry-run first:** `phaseone retention --dry-run`
2. **Backup before restore:** `phaseone backup`
3. **Check health before operations:** `phaseone health`
4. **Use JSON output for scripting:** `phaseone health --json`

### Timeout Policy

Commands timeout after 270 seconds (4.5 minutes) by default. Long-running operations will be terminated and should be retried with smaller scope.

---

## Troubleshooting

### "Command not found" after npm link

```bash
# Check if linked
npm ls -g phaseone-core

# Relink
npm unlink -g phaseone-core
npm link
```

### "Connection refused" on health checks

1. Ensure Docker stack is running: `phaseone compose ps`
2. Check correct ports: `GATEWAY_URL` and `DASHBOARD_URL`
3. Wait for services to be healthy: `phaseone ready`

### "Permission denied" on backup

Ensure write access to `PHASEONE_BACKUP_DIR` (default: `./backups`).

### GUI won't start

1. Check if port is in use: `lsof -i :8888`
2. Try a different port: `phaseone gui --port 9000`
3. Check for TypeScript errors: `npm run build`

### Retention deletes nothing

1. Check `--days` matches your retention policy
2. Ensure `DATABASE_URL` is correct
3. Run `--dry-run` first to see what would be deleted

### Windows: "bash: command not found"

Install Git for Windows (includes Git Bash) or use WSL:

```powershell
wsl bash scripts/restore.sh backups/20260916-143000
```

### Module resolution errors

Ensure you've run `npm install`:

```bash
npm install
npm run phaseone -- version
```

---

## License

MIT — Copyright (c) 2026 **Veracity Integrity LLC**

https://VeracityIntegrity.com

DEFENSIVE ONLY — no exploit tooling.
