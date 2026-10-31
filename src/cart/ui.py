"""Local zero-dependency web dashboard for CyberForge CART.

Serves an interactive dark-mode control page on localhost using Python's
built-in http.server. Reads live telemetry directly from SQLite (cart.db)
and allows organisers and judges to inspect:
- Multi-agent live coordination status (Network, Web, Binary, Verifier, Advisor)
- Captured CTF flags trophy case (flag{...}, CyberForge{...})
- Live worker concurrency and PRD compliance metrics
- Real-time PolicyGate audit logs (proving 0 out-of-scope probes)
- Interactive visual attack path graph (SVG) with click-to-inspect nodes
- Consolidated Markdown report & downloadable code patches
"""

from __future__ import annotations

import http.server
import json
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any

from .advisor import RemediationAdvisor
from .attackpath import AttackPathBuilder
from .preflight import list_candidate_networks
from .report import ReportGenerator
from .store import connect

_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberForge CART — Live Autonomous Operations</title>
<style>
:root {
  --bg: #070a13;
  --panel: #0d1322;
  --panel-border: #1a233a;
  --text: #e5e7eb;
  --text-muted: #8892b0;
  --accent: #00f0ff;
  --accent-glow: rgba(0, 240, 255, 0.25);
  --gold: #f59e0b;
  --gold-glow: rgba(245, 158, 11, 0.25);
  --green: #10b981;
  --red: #ef4444;
  --purple: #8b5cf6;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
body { background: var(--bg); color: var(--text); padding: 1.5rem; line-height: 1.5; }
header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--panel-border); padding-bottom: 1rem; margin-bottom: 1.2rem; }
.logo { font-size: 1.4rem; font-weight: 800; letter-spacing: 1px; color: #fff; display: flex; align-items: center; gap: 0.6rem; }
.logo span { color: var(--accent); }
.badge { font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 9999px; text-transform: uppercase; font-weight: 700; }
.badge-running { background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }
.badge-partial { background: rgba(245, 158, 11, 0.2); color: var(--gold); border: 1px solid var(--gold); }
.badge-completed { background: rgba(0, 240, 255, 0.2); color: var(--accent); border: 1px solid var(--accent); }
.badge-idle { background: rgba(156, 163, 175, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }

.grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 1rem; margin-bottom: 1.2rem; }
.col-3 { grid-column: span 3; }
.col-4 { grid-column: span 4; }
.col-6 { grid-column: span 6; }
.col-8 { grid-column: span 8; }
.col-12 { grid-column: span 12; }

.card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 8px; padding: 1rem; }
.card-header { font-size: 0.85rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.8rem; display: flex; justify-content: space-between; align-items: center; }
.metric-val { font-size: 1.8rem; font-weight: 800; color: #fff; margin-bottom: 0.2rem; }
.metric-sub { font-size: 0.75rem; color: var(--text-muted); }

/* Trophy Case */
.trophy-case { background: linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(13, 19, 34, 0.8) 100%); border: 1px solid var(--gold); box-shadow: 0 0 15px var(--gold-glow); border-radius: 8px; padding: 1rem; margin-bottom: 1.2rem; }
.flag-chip { display: inline-flex; align-items: center; gap: 0.5rem; background: rgba(245, 158, 11, 0.15); border: 1px solid var(--gold); color: #fff; padding: 0.3rem 0.8rem; border-radius: 6px; font-family: monospace; font-size: 0.9rem; font-weight: 700; margin: 0.3rem; }
.flag-meta { font-size: 0.65rem; font-weight: 400; color: var(--gold); opacity: 0.85; font-family: system-ui, sans-serif; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.btn-copy { background: var(--gold); color: #000; border: none; padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.7rem; font-weight: bold; cursor: pointer; }

/* Multi-Agent Strip */
.agent-strip { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; margin-bottom: 1.2rem; }
.agent-card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px; padding: 0.75rem; display: flex; flex-direction: column; gap: 0.3rem; }
.agent-name { font-size: 0.8rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.4rem; }
.agent-role { font-size: 0.7rem; color: var(--text-muted); }
.agent-stat { font-size: 0.75rem; font-weight: 600; color: var(--accent); }

table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--panel-border); }
th { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
tr:last-child td { border-bottom: none; }

.log-box { font-family: Consolas, monospace; font-size: 0.8rem; height: 260px; overflow-y: auto; background: #05080f; padding: 0.75rem; border-radius: 4px; border: 1px solid #141c2e; }
.log-line { margin-bottom: 0.3rem; }
.log-deny { color: var(--red); }
.log-allow { color: var(--green); }
.log-meta { color: var(--text-muted); }

.graph-container { width: 100%; height: 320px; background: #05080f; border: 1px solid #141c2e; border-radius: 6px; overflow: hidden; display: flex; align-items: center; justify-content: center; position: relative; }
svg { width: 100%; height: 100%; }

button { background: var(--accent); color: #000; border: none; padding: 0.5rem 1rem; border-radius: 4px; font-weight: 700; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
button:hover { background: #38f9d7; box-shadow: 0 0 12px var(--accent-glow); }
button.btn-sec { background: transparent; border: 1px solid var(--panel-border); color: var(--text); }
button.btn-sec:hover { background: var(--panel-border); }

pre.report-pre { white-space: pre-wrap; font-family: Consolas, monospace; font-size: 0.8rem; background: #05080f; padding: 1rem; border-radius: 6px; max-height: 400px; overflow-y: auto; }

/* Modal Drawer */
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 100; align-items: center; justify-content: center; }
.modal-content { background: var(--panel); border: 1px solid var(--accent); border-radius: 8px; width: 550px; max-width: 90%; max-height: 80vh; overflow-y: auto; padding: 1.5rem; box-shadow: 0 0 20px var(--accent-glow); }
</style>
</head>
<body>

<header>
  <div class="logo">
    ⚡ <span>CyberForge</span> CART
    <span id="run-badge" class="badge badge-idle">IDLE</span>
  </div>
  <div style="display:flex; gap:0.5rem; align-items:center;">
    <span id="run-timer" style="font-family:monospace; font-size:0.9rem; color:var(--text-muted);">00:00:00</span>
    <button onclick="downloadPatches()" class="btn-sec" style="color:var(--accent); border-color:var(--accent);">💾 Export Patches</button>
    <button onclick="refreshData()" class="btn-sec">↻ Refresh</button>
  </div>
</header>

<!-- Multi-Agent Live Coordination Strip -->
<div class="agent-strip" id="agents-strip">
  <div class="agent-card">
    <div class="agent-name">🌐 Network Specialist</div>
    <div class="agent-role">Host & Port Discovery</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">🕷️ Web Specialist</div>
    <div class="agent-role">Endpoints & Form Crawler</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">⚙️ Binary Specialist</div>
    <div class="agent-role">Static Analysis & Unsafe Libc</div>
    <div class="agent-stat">0 Active / 0 Done</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">🛡️ Verification Service</div>
    <div class="agent-role">Deterministic Playbooks</div>
    <div class="agent-stat">0 Confirmed</div>
  </div>
  <div class="agent-card">
    <div class="agent-name">💡 Remediation Advisor</div>
    <div class="agent-role">Plain-English Patches</div>
    <div class="agent-stat">0 Patches Ready</div>
  </div>
</div>

<!-- Planted CTF Flags Trophy Case -->
<div class="trophy-case" id="trophy-case" style="display:none;">
  <div style="font-size:0.85rem; font-weight:800; color:var(--gold); display:flex; align-items:center; gap:0.4rem; margin-bottom:0.5rem;">
    🚩 CAPTURED CTF PLANTED FLAGS (<span id="flag-count">0</span>)
  </div>
  <div id="flag-chips-list"></div>
</div>

<!-- PRD Metrics Summary -->
<div class="grid">
  <div class="col-3 card">
    <div class="card-header">Scope Safety</div>
    <div class="metric-val" id="metric-safety" style="color:var(--green)">0 Leaks</div>
    <div class="metric-sub" id="metric-safety-sub">0 out-of-scope probes blocked</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Autonomy Post-Start</div>
    <div class="metric-val" style="color:var(--accent)">100%</div>
    <div class="metric-sub">0 human interventions required</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Verified Findings</div>
    <div class="metric-val" id="metric-findings">0 / 0</div>
    <div class="metric-sub" id="metric-findings-sub">100% verification rate</div>
  </div>
  <div class="col-3 card">
    <div class="card-header">Discovered Assets</div>
    <div class="metric-val" id="metric-assets">0</div>
    <div class="metric-sub" id="metric-services">0 open services identified</div>
  </div>
</div>

<!-- Main Visualization & Audit -->
<div class="grid">
  <!-- Interactive Attack Path Graph -->
  <div class="col-8 card">
    <div class="card-header">
      <span>Evidence-Backed Attack Graph</span>
      <span style="font-size:0.75rem; color:var(--text-muted)">Click any node to inspect details</span>
    </div>
    <div class="graph-container">
      <svg id="attack-graph-svg" viewBox="0 0 700 300">
        <text x="350" y="150" fill="#6b7280" text-anchor="middle" font-size="14">No attack paths generated yet. Run an assessment.</text>
      </svg>
    </div>
  </div>

  <!-- Live Scope Gate Audit Trail -->
  <div class="col-4 card">
    <div class="card-header">
      <span>PolicyGate Firewall Log</span>
      <span style="font-size:0.75rem; color:var(--green)">FAIL-CLOSED</span>
    </div>
    <div class="log-box" id="gate-logs">
      <div class="log-line log-meta">[+] Awaiting gate activity...</div>
    </div>
  </div>
</div>

<!-- Findings & Discovered Inventory -->
<div class="grid">
  <div class="col-6 card">
    <div class="card-header">Confirmed Weaknesses & Findings</div>
    <div style="max-height: 250px; overflow-y: auto;">
      <table id="findings-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Evidence ID</th>
          </tr>
        </thead>
        <tbody>
          <tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No findings recorded</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="col-6 card">
    <div class="card-header">Asset & Service Inventory</div>
    <div style="max-height: 250px; overflow-y: auto;">
      <table id="inventory-table">
        <thead>
          <tr>
            <th>Target Key</th>
            <th>Type</th>
            <th>Open Services</th>
          </tr>
        </thead>
        <tbody>
          <tr><td colspan="3" style="color:var(--text-muted); text-align:center;">No assets cataloged</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Executive Report Tab -->
<div class="grid">
  <div class="col-12 card">
    <div class="card-header">
      <span>Latest Consolidated Assessment Report</span>
      <button onclick="downloadReport()" class="btn-sec" style="font-size:0.75rem; padding:0.2rem 0.5rem;">Download Markdown</button>
    </div>
    <pre class="report-pre" id="report-text">No report generated yet.</pre>
  </div>
</div>

<!-- Node Inspection Modal -->
<div class="modal-overlay" id="node-modal" onclick="closeModal(event)">
  <div class="modal-content" onclick="event.stopPropagation()">
    <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--panel-border); padding-bottom:0.5rem; margin-bottom:1rem;">
      <h3 id="modal-title" style="color:var(--accent);">Host Details</h3>
      <button onclick="document.getElementById('node-modal').style.display='none'" class="btn-sec" style="padding:0.2rem 0.5rem;">✕</button>
    </div>
    <div id="modal-body" style="font-size:0.85rem; line-height:1.6;"></div>
  </div>
</div>

<script>
let lastReportContent = "";

async function refreshData() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    renderStatus(data);
    
    const logsRes = await fetch('/api/logs');
    const logsData = await logsRes.json();
    renderLogs(logsData);

    const invRes = await fetch('/api/inventory');
    const invData = await invRes.json();
    renderInventory(invData);

    const fRes = await fetch('/api/findings');
    const fData = await fRes.json();
    renderFindings(fData);

    const gRes = await fetch('/api/graph');
    const gData = await gRes.json();
    renderGraph(gData);

    const flagsRes = await fetch('/api/flags');
    const flagsData = await flagsRes.json();
    renderFlags(flagsData);

    const agentsRes = await fetch('/api/agents');
    const agentsData = await agentsRes.json();
    renderAgents(agentsData);

    const repRes = await fetch('/api/report');
    const repData = await repRes.json();
    if (repData.report) {
      document.getElementById('report-text').textContent = repData.report;
      lastReportContent = repData.report;
    }
  } catch (err) {
    console.error('Fetch error:', err);
  }
}

function renderStatus(data) {
  const badge = document.getElementById('run-badge');
  badge.textContent = data.status.toUpperCase();
  badge.className = 'badge ' + (
    data.status === 'running' ? 'badge-running' :
    data.status === 'partial' ? 'badge-partial' :
    data.status === 'completed' ? 'badge-completed' : 'badge-idle'
  );

  document.getElementById('metric-safety').textContent = `${data.metrics.scope_safety_out_of_bounds_probes} Leaks`;
  document.getElementById('metric-safety-sub').textContent = `${data.metrics.scope_decisions_denied} out-of-scope probes blocked`;
  document.getElementById('metric-findings').textContent = `${data.metrics.confirmed_findings} / ${data.metrics.total_findings}`;
  document.getElementById('metric-findings-sub').textContent = `${data.metrics.verification_rate_pct}% verification rate`;
  document.getElementById('metric-assets').textContent = data.metrics.total_assets_discovered;
  document.getElementById('metric-services').textContent = `${data.metrics.total_services_discovered} open services identified`;
  document.getElementById('run-timer').textContent = `${data.metrics.runtime_seconds}s`;
}

function renderAgents(agents) {
  if (!agents || !agents.length) return;
  const strip = document.getElementById('agents-strip');
  strip.innerHTML = agents.map(a => `
    <div class="agent-card">
      <div class="agent-name">${a.icon} ${a.name}</div>
      <div class="agent-role">${a.role}</div>
      <div class="agent-stat">${a.active} In Flight / ${a.completed} Done</div>
    </div>
  `).join('');
}

function renderFlags(flags) {
  const caseBox = document.getElementById('trophy-case');
  if (!flags || !flags.length) {
    caseBox.style.display = 'none';
    return;
  }
  caseBox.style.display = 'block';
  document.getElementById('flag-count').textContent = flags.length;
  const list = document.getElementById('flag-chips-list');
  list.innerHTML = flags.map((f, idx) => {
    const flagVal = f.excerpt.split(';').find(p => p.includes('flag='))?.split('=')[1] || f.summary;
    return `
      <div class="flag-chip">
        <span>🚩 ${flagVal}</span>
        <span class="flag-meta" title="${f.source}">📍 ${f.source || 'unknown source'}</span>
        <span class="flag-meta">🕒 ${f.captured_at || '—'}</span>
        <span class="flag-meta">${f.status || 'candidate'}</span>
        <button class="btn-copy" data-flag="${flagVal}" id="copy-flag-${idx}">Copy Flag ⧉</button>
      </div>
    `;
  }).join('');
  // Bind copy handlers without inline string interpolation (safe against quotes)
  list.querySelectorAll('.btn-copy[data-flag]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const val = btn.getAttribute('data-flag');
      try {
        await navigator.clipboard.writeText(val);
        btn.textContent = '✓ Copied';
      } catch (err) {
        // Clipboard API unavailable — fallback via temporary textarea
        const ta = document.createElement('textarea');
        ta.value = val;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        btn.textContent = '✓ Copied';
      }
      setTimeout(() => { btn.textContent = 'Copy Flag ⧉'; }, 1500);
    });
  });
}

function renderLogs(logs) {
  const box = document.getElementById('gate-logs');
  if (!logs || !logs.length) return;
  box.innerHTML = logs.map(l => {
    const isDeny = l.decision === 'deny';
    const cls = isDeny ? 'log-deny' : 'log-allow';
    const tag = isDeny ? '[BLOCKED]' : '[ALLOWED]';
    return `<div class="log-line ${cls}"><span class="log-meta">${l.at.slice(11, 19)}</span> ${tag} ${l.target} - ${l.reason}</div>`;
  }).join('');
}

function renderInventory(inv) {
  const tbody = document.querySelector('#inventory-table tbody');
  if (!inv || !inv.length) {
    tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted); text-align:center;">No assets cataloged</td></tr>';
    return;
  }
  tbody.innerHTML = inv.map(a => {
    const svcs = a.services.map(s => `${s.port}/${s.protocol} (${s.name})`).join(', ') || 'None';
    return `<tr><td><code>${a.canonical_key}</code></td><td>${a.type}</td><td>${svcs}</td></tr>`;
  }).join('');
}

function renderFindings(findings) {
  const tbody = document.querySelector('#findings-table tbody');
  if (!findings || !findings.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No findings recorded</td></tr>';
    return;
  }
  tbody.innerHTML = findings.map(f => {
    const sevColor = f.severity === 'critical' ? 'var(--red)' : f.severity === 'high' ? 'var(--gold)' : 'var(--accent)';
    return `<tr>
      <td>${f.type}</td>
      <td style="color:${sevColor}; font-weight:700;">${f.severity.toUpperCase()}</td>
      <td><code>${f.status}</code></td>
      <td>${f.evidence_count} evidence ref(s)</td>
    </tr>`;
  }).join('');
}

function renderGraph(graphData) {
  const svg = document.getElementById('attack-graph-svg');
  if (!graphData.nodes || !graphData.nodes.length) {
    svg.innerHTML = '<text x="350" y="150" fill="#6b7280" text-anchor="middle" font-size="14">No attack paths generated yet. Run an assessment.</text>';
    return;
  }

  const nodes = graphData.nodes;
  const edges = graphData.edges;
  let html = `<defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
    </marker>
  </defs>`;

  // Draw Edges
  edges.forEach(e => {
    const src = nodes.find(n => n.id === e.source);
    const dst = nodes.find(n => n.id === e.target);
    if (src && dst) {
      html += `<line x1="${src.x}" y1="${src.y}" x2="${dst.x}" y2="${dst.y}" stroke="#ef4444" stroke-width="2.5" marker-end="url(#arrow)" stroke-dasharray="4" />`;
      const midX = (src.x + dst.x) / 2;
      const midY = (src.y + dst.y) / 2 - 8;
      html += `<text x="${midX}" y="${midY}" fill="#f59e0b" font-size="10" font-family="monospace" text-anchor="middle">${e.technique}</text>`;
    }
  });

  // Draw Nodes
  nodes.forEach(n => {
    const isTarget = n.type === 'target';
    const isEntry = n.type === 'entry';
    const color = isTarget ? '#ef4444' : isEntry ? '#00f0ff' : '#10b981';
    html += `<g transform="translate(${n.x},${n.y})" style="cursor:pointer;" onclick="inspectNode('${n.id}')">
      <circle r="16" fill="#111827" stroke="${color}" stroke-width="3" />
      <text y="4" fill="#fff" font-size="10" font-weight="bold" text-anchor="middle">${n.label.slice(0,3)}</text>
      <text y="28" fill="#e5e7eb" font-size="10" font-family="monospace" text-anchor="middle">${n.label}</text>
    </g>`;
  });

  svg.innerHTML = html;
}

async function inspectNode(assetId) {
  try {
    const res = await fetch(`/api/asset?id=${encodeURIComponent(assetId)}`);
    const data = await res.json();
    if (data.error) return;

    document.getElementById('modal-title').textContent = `Target: ${data.canonical_key} (${data.type})`;
    let body = `
      <p><strong>Asset ID:</strong> <code>${data.asset_id}</code></p>
      <p><strong>First Seen:</strong> ${data.first_seen}</p>
      <h4 style="margin-top:1rem; color:var(--accent);">Open Services (${data.services.length})</h4>
      <ul style="margin-left:1.2rem; margin-top:0.3rem;">
        ${data.services.map(s => `<li><code>${s.port}/${s.protocol}</code> - ${s.name} ${s.version || ''}</li>`).join('') || '<li>None</li>'}
      </ul>
      <h4 style="margin-top:1rem; color:var(--gold);">Findings & Weaknesses (${data.findings.length})</h4>
      <ul style="margin-left:1.2rem; margin-top:0.3rem;">
        ${data.findings.map(f => `<li><strong>${f.severity.toUpperCase()}:</strong> ${f.type} - <em>${f.summary}</em></li>`).join('') || '<li>No direct weaknesses found on this host</li>'}
      </ul>
    `;
    document.getElementById('modal-body').innerHTML = body;
    document.getElementById('node-modal').style.display = 'flex';
  } catch (err) {
    console.error(err);
  }
}

function closeModal(event) {
  document.getElementById('node-modal').style.display = 'none';
}

function downloadReport() {
  if (!lastReportContent) return alert('No report available to download.');
  const blob = new Blob([lastReportContent], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'cart_assessment_report.md';
  a.click();
}

async function downloadPatches() {
  try {
    const res = await fetch('/api/patches');
    const data = await res.json();
    if (!data.patches || !data.patches.length) {
      alert('No confirmed vulnerabilities require code patches yet.');
      return;
    }
    alert(`Successfully generated ${data.patches.length} patch file(s) in reports/patches/!`);
  } catch (err) {
    alert('Error generating patches: ' + err);
  }
}

// Initial fetch & 1-second auto-refresh
refreshData();
setInterval(refreshData, 1000);
</script>
</body>
</html>
"""


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """Zero-dependency HTTP request handler for the CART local UI."""

    conn: sqlite3.Connection
    db_path: str

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self._send_html(_INDEX_HTML)
        elif path == "/api/status":
            self._handle_status()
        elif path == "/api/candidates":
            self._handle_candidates()
        elif path == "/api/inventory":
            self._handle_inventory()
        elif path == "/api/findings":
            self._handle_findings()
        elif path == "/api/graph":
            self._handle_graph()
        elif path == "/api/flags":
            self._handle_flags()
        elif path == "/api/agents":
            self._handle_agents()
        elif path == "/api/asset":
            self._handle_asset_detail(parsed.query)
        elif path == "/api/patches":
            self._handle_patches()
        elif path == "/api/logs":
            self._handle_logs()
        elif path == "/api/report":
            self._handle_report()
        else:
            self._send_json({"error": "not found"}, status=404)

    def _send_html(self, content: str) -> None:
        raw = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle_status(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        run_row = conn.execute(
            "SELECT run_id, status, tier, started_at, completed_at, scope_version FROM runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()

        if not run_row:
            self._send_json({
                "status": "idle",
                "tier": "standard",
                "metrics": {
                    "scope_safety_out_of_bounds_probes": 0,
                    "scope_decisions_denied": 0,
                    "total_assets_discovered": 0,
                    "total_services_discovered": 0,
                    "total_findings": 0,
                    "confirmed_findings": 0,
                    "verification_rate_pct": 100.0,
                    "runtime_seconds": 0.0,
                },
            })
            conn.close()
            return

        run_id, status, tier, start, end, scope_ver = run_row
        reporter = ReportGenerator(conn)
        report_data = reporter._collect_data(run_id)

        self._send_json({
            "run_id": run_id,
            "status": status,
            "tier": tier,
            "scope_version": scope_ver,
            "started_at": start,
            "completed_at": end,
            "metrics": report_data["metrics"],
        })
        conn.close()

    def _handle_flags(self) -> None:
        """Captured CTF flags — real records from the findings/evidence tables."""
        conn = connect(self.db_path, check_same_thread=False)
        rows = conn.execute(
            "SELECT finding_id, asset_id, severity, status, summary "
            "FROM findings WHERE finding_type = 'ctf_planted_flag' "
            "ORDER BY rowid"
        ).fetchall()
        asset_keys = dict(
            conn.execute("SELECT asset_id, canonical_key FROM assets").fetchall()
        )
        flags = []
        for fid, aid, severity, status, summary in rows:
            ev = conn.execute(
                "SELECT artifact_path, excerpt, hash, timestamp "
                "FROM evidence WHERE finding_id = ? LIMIT 1",
                (fid,),
            ).fetchone()
            flags.append({
                "finding_id": fid,
                "asset_id": aid,
                "asset_key": asset_keys.get(aid, aid),
                "severity": severity,
                "status": status,
                "summary": summary,
                "location": ev[0] if ev else "",
                "excerpt": ev[1] if ev else "",
                "hash": ev[2] if ev else "",
                # Exact capture timestamp from the evidence record (UTC)
                "captured_at": ev[3] if ev else "",
                # Source: crawled page URL (web) or binary file path (binary)
                "source": ev[0] if ev else "",
            })
        conn.close()
        self._send_json(flags)

    def _handle_agents(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        agents = {
            "network": {"name": "Network Specialist", "icon": "🌐", "role": "Host & Port Discovery", "active": 0, "completed": 0},
            "web": {"name": "Web Specialist", "icon": "🕷️", "role": "Endpoints & Form Crawler", "active": 0, "completed": 0},
            "binary": {"name": "Binary Specialist", "icon": "⚙️", "role": "Static Analysis & Unsafe Libc", "active": 0, "completed": 0},
            "verifier": {"name": "Verification Service", "icon": "🛡️", "role": "Deterministic Playbooks", "active": 0, "completed": 0},
            "advisor": {"name": "Remediation Advisor", "icon": "💡", "role": "Plain-English Patches", "active": 0, "completed": 0},
        }

        task_rows = conn.execute("SELECT owner, status, count(*) FROM tasks GROUP BY owner, status").fetchall()
        for owner, status, count in task_rows:
            if owner in agents:
                if status == "running":
                    agents[owner]["active"] += count
                elif status == "succeeded":
                    agents[owner]["completed"] += count

        conf_count = conn.execute("SELECT count(*) FROM findings WHERE status = 'confirmed'").fetchone()[0]
        cand_count = conn.execute("SELECT count(*) FROM findings WHERE status = 'candidate'").fetchone()[0]
        agents["verifier"]["active"] = cand_count
        agents["verifier"]["completed"] = conf_count
        agents["advisor"]["completed"] = conf_count

        conn.close()
        self._send_json(list(agents.values()))

    def _handle_asset_detail(self, query_str: str) -> None:
        qs = urllib.parse.parse_qs(query_str)
        asset_id = qs.get("id", [""])[0]
        conn = connect(self.db_path, check_same_thread=False)
        a_row = conn.execute(
            "SELECT asset_id, canonical_key, asset_type, first_seen FROM assets WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        if not a_row:
            conn.close()
            self._send_json({"error": "not found"}, status=404)
            return

        svcs = conn.execute(
            "SELECT port, protocol, service_name, version, state FROM services WHERE asset_id = ?",
            (asset_id,),
        ).fetchall()
        findings = conn.execute(
            "SELECT finding_id, finding_type, severity, status, summary FROM findings WHERE asset_id = ?",
            (asset_id,),
        ).fetchall()
        conn.close()
        self._send_json({
            "asset_id": a_row[0],
            "canonical_key": a_row[1],
            "type": a_row[2],
            "first_seen": a_row[3],
            "services": [{"port": s[0], "protocol": s[1], "name": s[2], "version": s[3]} for s in svcs],
            "findings": [{"id": f[0], "type": f[1], "severity": f[2], "status": f[3], "summary": f[4]} for f in findings],
        })

    def _handle_patches(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        advisor = RemediationAdvisor(conn)
        patches = advisor.export_patches()
        conn.close()
        self._send_json({"patches": patches})

    def _handle_candidates(self) -> None:
        candidates = list_candidate_networks()
        self._send_json(candidates)

    def _handle_inventory(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        assets = conn.execute(
            "SELECT asset_id, canonical_key, asset_type, first_seen FROM assets"
        ).fetchall()

        inv = []
        for a_id, key, atype, seen in assets:
            svcs = conn.execute(
                "SELECT port, protocol, service_name FROM services WHERE asset_id = ?",
                (a_id,),
            ).fetchall()
            inv.append({
                "asset_id": a_id,
                "canonical_key": key,
                "type": atype,
                "first_seen": seen,
                "services": [
                    {"port": s[0], "protocol": s[1], "name": s[2]} for s in svcs
                ],
            })
        conn.close()
        self._send_json(inv)

    def _handle_findings(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        rows = conn.execute(
            "SELECT finding_id, finding_type, severity, status, summary FROM findings"
        ).fetchall()
        findings = []
        for fid, ftype, sev, st, summary in rows:
            ev_cnt = conn.execute(
                "SELECT count(*) FROM evidence WHERE finding_id = ?", (fid,)
            ).fetchone()[0]
            findings.append({
                "finding_id": fid,
                "type": ftype,
                "severity": sev,
                "status": st,
                "summary": summary,
                "evidence_count": ev_cnt,
            })
        conn.close()
        self._send_json(findings)

    def _handle_logs(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        rows = conn.execute(
            "SELECT requested_target, decision, reason, at FROM scope_decisions_log ORDER BY at DESC LIMIT 50"
        ).fetchall()
        logs = [
            {"target": r[0], "decision": r[1], "reason": r[2], "at": r[3]}
            for r in rows
        ]
        conn.close()
        self._send_json(logs)

    def _handle_graph(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        builder = AttackPathBuilder(conn, "current")
        paths = builder.build()

        nodes_dict: dict[str, dict[str, Any]] = {}
        edges_list: list[dict[str, Any]] = []

        x_start = 80
        y_center = 150

        asset_names = dict(conn.execute("SELECT asset_id, canonical_key FROM assets").fetchall())

        for p_idx, path in enumerate(paths):
            for step_idx, e in enumerate(path.edges):
                src_name = asset_names.get(e.source_id, e.source_id)
                dst_name = asset_names.get(e.target_id, e.target_id)

                if e.source_id not in nodes_dict:
                    nodes_dict[e.source_id] = {
                        "id": e.source_id,
                        "label": src_name,
                        "x": x_start + len(nodes_dict) * 120,
                        "y": y_center + ((len(nodes_dict) % 2) * 50 - 25),
                        "type": "entry" if step_idx == 0 else "pivot",
                    }
                if e.target_id not in nodes_dict:
                    nodes_dict[e.target_id] = {
                        "id": e.target_id,
                        "label": dst_name,
                        "x": x_start + len(nodes_dict) * 120,
                        "y": y_center + ((len(nodes_dict) % 2) * 50 - 25),
                        "type": "target" if step_idx == len(path.edges) - 1 else "pivot",
                    }

                edges_list.append({
                    "source": e.source_id,
                    "target": e.target_id,
                    "technique": e.relationship_type,
                    "confidence": e.confidence_label,
                })

        conn.close()
        self._send_json({
            "nodes": list(nodes_dict.values()),
            "edges": edges_list,
        })

    def _handle_report(self) -> None:
        conn = connect(self.db_path, check_same_thread=False)
        rep_row = conn.execute(
            "SELECT path FROM report_artifacts WHERE format = 'md' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

        report_text = ""
        if rep_row and Path(rep_row[0]).exists():
            report_text = Path(rep_row[0]).read_text(encoding="utf-8")

        conn.close()
        self._send_json({"report": report_text})


def run_dashboard_server(
    db_path: str = "cart.db",
    host: str = "127.0.0.1",
    port: int = 8080,
    open_browser: bool = False,
) -> http.server.HTTPServer:
    """Launch the local HTTP dashboard server."""
    class BoundHandler(DashboardHandler):
        pass

    BoundHandler.db_path = db_path

    server = http.server.HTTPServer((host, port), BoundHandler)
    url = f"http://{host}:{port}/"
    print(f"\n[+] CyberForge CART UI Dashboard running at: {url}")
    print("[+] Press Ctrl+C in terminal to stop dashboard server.")

    if open_browser:
        import webbrowser
        webbrowser.open(url)

    return server
