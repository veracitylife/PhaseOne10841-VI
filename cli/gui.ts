#!/usr/bin/env node
/**
 * PhaseOne10841 CLI GUI — Lightweight local web UI
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 *
 * A simple Hono-based web server that exposes CLI commands through a browser interface.
 * No Electron required — just a local HTTP server with a clean UI.
 *
 * DEFENSIVE ONLY — no exploit tooling.
 */

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { 
  commands, 
  executeCommand, 
  VERSION, 
  PRODUCT_NAME, 
  COMPANY, 
  WEBSITE,
  BANNER,
  type CommandResult 
} from './registry.js';

const app = new Hono();

app.use('*', cors());

const HTML_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${PRODUCT_NAME} CLI GUI</title>
  <style>
    :root {
      --bg: #0f172a;
      --surface: #1e293b;
      --surface-2: #334155;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --success: #22c55e;
      --error: #ef4444;
      --warning: #f59e0b;
      --border: #475569;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      text-align: center;
      margin-bottom: 2rem;
      padding: 1.5rem;
      background: var(--surface);
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
    .subtitle { color: var(--text-muted); font-size: 0.9rem; }
    .company { color: var(--accent); font-size: 0.85rem; margin-top: 0.5rem; }
    .warning-banner {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid var(--warning);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      margin-top: 1rem;
      font-size: 0.85rem;
      color: var(--warning);
    }
    .grid {
      display: grid;
      grid-template-columns: 300px 1fr;
      gap: 1.5rem;
    }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
    }
    .sidebar {
      background: var(--surface);
      border-radius: 12px;
      padding: 1rem;
      border: 1px solid var(--border);
      height: fit-content;
    }
    .sidebar h2 {
      font-size: 1rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }
    .cmd-list { list-style: none; }
    .cmd-item {
      padding: 0.75rem;
      margin-bottom: 0.5rem;
      background: var(--surface-2);
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
      border: 1px solid transparent;
    }
    .cmd-item:hover { border-color: var(--accent); }
    .cmd-item.active { border-color: var(--accent); background: rgba(59, 130, 246, 0.1); }
    .cmd-item.dangerous { border-left: 3px solid var(--warning); }
    .cmd-name { font-weight: 600; font-size: 0.9rem; }
    .cmd-desc { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }
    .main {
      background: var(--surface);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
    }
    .main h2 { font-size: 1.25rem; margin-bottom: 0.5rem; }
    .usage { font-family: monospace; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem; }
    .options {
      background: var(--surface-2);
      border-radius: 8px;
      padding: 1rem;
      margin-bottom: 1rem;
    }
    .options h3 { font-size: 0.9rem; margin-bottom: 0.75rem; }
    .option-group { margin-bottom: 0.75rem; }
    .option-group label { display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.25rem; }
    input[type="text"], input[type="number"] {
      width: 100%;
      padding: 0.5rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 0.9rem;
    }
    input:focus { outline: none; border-color: var(--accent); }
    .checkbox-group {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    input[type="checkbox"] { width: 16px; height: 16px; }
    .actions {
      display: flex;
      gap: 0.75rem;
      margin-bottom: 1rem;
    }
    button {
      padding: 0.75rem 1.5rem;
      border: none;
      border-radius: 8px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-primary { background: var(--accent); color: white; }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-primary:disabled { background: var(--surface-2); cursor: not-allowed; }
    .btn-secondary { background: var(--surface-2); color: var(--text); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--border); }
    .btn-danger { background: var(--error); color: white; }
    .btn-danger:hover { background: #dc2626; }
    .output-container {
      background: var(--bg);
      border-radius: 8px;
      border: 1px solid var(--border);
      overflow: hidden;
    }
    .output-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.75rem 1rem;
      background: var(--surface-2);
      border-bottom: 1px solid var(--border);
    }
    .output-title { font-size: 0.85rem; font-weight: 600; }
    .status-badge {
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .status-success { background: rgba(34, 197, 94, 0.2); color: var(--success); }
    .status-error { background: rgba(239, 68, 68, 0.2); color: var(--error); }
    .status-running { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
    .output {
      padding: 1rem;
      font-family: 'SF Mono', Monaco, 'Courier New', monospace;
      font-size: 0.8rem;
      line-height: 1.6;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 500px;
      overflow-y: auto;
    }
    .confirm-modal {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .confirm-modal.hidden { display: none; }
    .confirm-content {
      background: var(--surface);
      border-radius: 12px;
      padding: 2rem;
      max-width: 400px;
      border: 1px solid var(--border);
    }
    .confirm-content h3 { margin-bottom: 1rem; }
    .confirm-content p { color: var(--text-muted); margin-bottom: 1.5rem; }
    .confirm-actions { display: flex; gap: 0.75rem; justify-content: flex-end; }
    footer {
      text-align: center;
      margin-top: 2rem;
      padding: 1rem;
      color: var(--text-muted);
      font-size: 0.8rem;
    }
    footer a { color: var(--accent); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ ${PRODUCT_NAME}</h1>
      <div class="subtitle">Defensive Agent Security Gateway (Agent EDR) — CLI GUI v${VERSION}</div>
      <div class="company">A product of ${COMPANY}</div>
      <div class="warning-banner">⚠️ DEFENSIVE ONLY — no exploit tooling. Commands marked ⚠️ modify data.</div>
    </header>

    <div class="grid">
      <aside class="sidebar">
        <h2>Commands</h2>
        <ul class="cmd-list" id="cmdList"></ul>
      </aside>

      <main class="main">
        <div id="cmdDetail">
          <h2 id="cmdTitle">Select a command</h2>
          <div class="usage" id="cmdUsage"></div>
          <div class="options" id="cmdOptions" style="display:none;">
            <h3>Options</h3>
            <div id="optionsForm"></div>
          </div>
          <div class="actions" id="cmdActions" style="display:none;">
            <button class="btn-primary" id="runBtn">Run Command</button>
            <button class="btn-secondary" id="clearBtn">Clear Output</button>
          </div>
          <div class="output-container" id="outputContainer" style="display:none;">
            <div class="output-header">
              <span class="output-title">Output</span>
              <span class="status-badge" id="statusBadge"></span>
            </div>
            <div class="output" id="output"></div>
          </div>
        </div>
      </main>
    </div>

    <footer>
      <a href="${WEBSITE}" target="_blank">${COMPANY}</a> · ${WEBSITE}
    </footer>
  </div>

  <div class="confirm-modal hidden" id="confirmModal">
    <div class="confirm-content">
      <h3>⚠️ Confirm Action</h3>
      <p id="confirmMessage">This action may modify data. Are you sure you want to proceed?</p>
      <div class="confirm-actions">
        <button class="btn-secondary" id="cancelBtn">Cancel</button>
        <button class="btn-danger" id="proceedBtn">Proceed</button>
      </div>
    </div>
  </div>

  <script>
    const commands = ${JSON.stringify(commands.map(c => ({
      name: c.name,
      description: c.description,
      usage: c.usage,
      options: c.options,
      dangerous: c.dangerous,
      requiresConfirmation: c.requiresConfirmation,
    })))};

    let currentCommand = null;
    let pendingConfirm = null;

    function renderCommands() {
      const list = document.getElementById('cmdList');
      list.innerHTML = commands.map(cmd => 
        \`<li class="cmd-item \${cmd.dangerous ? 'dangerous' : ''}" data-cmd="\${cmd.name}">
          <div class="cmd-name">\${cmd.name} \${cmd.dangerous ? '⚠️' : ''}</div>
          <div class="cmd-desc">\${cmd.description}</div>
        </li>\`
      ).join('');

      list.querySelectorAll('.cmd-item').forEach(item => {
        item.addEventListener('click', () => selectCommand(item.dataset.cmd));
      });
    }

    function selectCommand(name) {
      currentCommand = commands.find(c => c.name === name);
      if (!currentCommand) return;

      document.querySelectorAll('.cmd-item').forEach(el => el.classList.remove('active'));
      document.querySelector(\`[data-cmd="\${name}"]\`)?.classList.add('active');

      document.getElementById('cmdTitle').textContent = currentCommand.name + (currentCommand.dangerous ? ' ⚠️' : '');
      document.getElementById('cmdUsage').textContent = currentCommand.usage;
      document.getElementById('cmdActions').style.display = 'flex';

      const optionsDiv = document.getElementById('cmdOptions');
      const form = document.getElementById('optionsForm');

      if (currentCommand.options?.length) {
        optionsDiv.style.display = 'block';
        form.innerHTML = currentCommand.options.map((opt, i) => {
          const isCheckbox = opt.flag.includes('--dry-run') || opt.flag.includes('--execute') || 
                            opt.flag.includes('--json') || opt.flag.includes('--confirm') ||
                            opt.flag.includes('--force');
          const flagName = opt.flag.split(',')[0].replace('--', '').replace(/ .*/,'');
          
          if (isCheckbox) {
            return \`<div class="option-group">
              <div class="checkbox-group">
                <input type="checkbox" id="opt_\${i}" data-flag="\${opt.flag.split(',')[0].trim()}">
                <label for="opt_\${i}">\${opt.flag} — \${opt.description}</label>
              </div>
            </div>\`;
          }
          
          return \`<div class="option-group">
            <label for="opt_\${i}">\${opt.flag}</label>
            <input type="text" id="opt_\${i}" placeholder="\${opt.default || opt.description}" 
                   data-flag="\${opt.flag.split(',')[0].trim().split(' ')[0]}">
          </div>\`;
        }).join('');

        if (currentCommand.requiresConfirmation) {
          form.innerHTML += \`<div class="option-group">
            <div class="checkbox-group">
              <input type="checkbox" id="opt_confirm" data-flag="--confirm">
              <label for="opt_confirm">--confirm — Confirm destructive action</label>
            </div>
          </div>\`;
        }
      } else {
        optionsDiv.style.display = 'none';
        form.innerHTML = '';
      }
    }

    function gatherArgs() {
      const args = [];
      const form = document.getElementById('optionsForm');
      form.querySelectorAll('input').forEach(input => {
        if (input.type === 'checkbox' && input.checked) {
          args.push(input.dataset.flag);
        } else if (input.type === 'text' && input.value.trim()) {
          args.push(input.dataset.flag, input.value.trim());
        }
      });
      return args;
    }

    async function runCommand(confirmed = false) {
      if (!currentCommand) return;

      const args = gatherArgs();
      
      if (currentCommand.requiresConfirmation && !confirmed && !args.includes('--confirm')) {
        pendingConfirm = { command: currentCommand.name, args };
        document.getElementById('confirmMessage').textContent = 
          \`The command "\${currentCommand.name}" may modify data. Are you sure you want to proceed?\`;
        document.getElementById('confirmModal').classList.remove('hidden');
        return;
      }

      const outputContainer = document.getElementById('outputContainer');
      const output = document.getElementById('output');
      const badge = document.getElementById('statusBadge');

      outputContainer.style.display = 'block';
      output.textContent = 'Running...';
      badge.textContent = 'Running';
      badge.className = 'status-badge status-running';
      document.getElementById('runBtn').disabled = true;

      try {
        const res = await fetch('/api/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            command: currentCommand.name, 
            args: confirmed ? [...args, '--confirm'] : args 
          }),
        });

        const result = await res.json();
        
        let text = result.output || '';
        if (result.error) text += '\\n\\nError: ' + result.error;
        output.textContent = text || '(no output)';
        
        badge.textContent = result.ok ? 'Success' : 'Error';
        badge.className = 'status-badge ' + (result.ok ? 'status-success' : 'status-error');
      } catch (err) {
        output.textContent = 'Request failed: ' + err.message;
        badge.textContent = 'Error';
        badge.className = 'status-badge status-error';
      } finally {
        document.getElementById('runBtn').disabled = false;
      }
    }

    document.getElementById('runBtn').addEventListener('click', () => runCommand(false));
    document.getElementById('clearBtn').addEventListener('click', () => {
      document.getElementById('output').textContent = '';
      document.getElementById('outputContainer').style.display = 'none';
    });

    document.getElementById('cancelBtn').addEventListener('click', () => {
      pendingConfirm = null;
      document.getElementById('confirmModal').classList.add('hidden');
    });

    document.getElementById('proceedBtn').addEventListener('click', () => {
      document.getElementById('confirmModal').classList.add('hidden');
      if (pendingConfirm) {
        runCommand(true);
        pendingConfirm = null;
      }
    });

    renderCommands();
    if (commands.length) selectCommand('help');
  </script>
</body>
</html>`;

app.get('/', (c) => {
  return c.html(HTML_PAGE);
});

app.get('/api/commands', (c) => {
  return c.json(commands.map((cmd) => ({
    name: cmd.name,
    description: cmd.description,
    usage: cmd.usage,
    options: cmd.options,
    dangerous: cmd.dangerous,
    requiresConfirmation: cmd.requiresConfirmation,
  })));
});

app.post('/api/execute', async (c) => {
  try {
    const body = await c.req.json() as { command: string; args?: string[] };
    const { command, args = [] } = body;

    if (!command) {
      return c.json({ ok: false, exitCode: 1, error: 'Missing command' }, 400);
    }

    const result = await executeCommand(command, args, {
      timeout: 270000,
    });

    return c.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ ok: false, exitCode: 1, error: msg }, 500);
  }
});

app.get('/api/health', (c) => {
  return c.json({ status: 'ok', version: VERSION });
});

function parseArgs(): { port: number } {
  const args = process.argv.slice(2);
  let port = 8888;
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === '--port' || args[i] === '-p') && args[i + 1]) {
      port = parseInt(args[++i], 10);
    }
  }
  return { port };
}

const { port } = parseArgs();

console.log(BANNER);
console.log('');
console.log(`${PRODUCT_NAME} CLI GUI`);
console.log(`Local server running at http://localhost:${port}`);
console.log(`${COMPANY} · ${WEBSITE}`);
console.log('');
console.log('Press Ctrl+C to stop');

serve({
  fetch: app.fetch,
  port,
});
