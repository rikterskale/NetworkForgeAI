"""Single-file operator console served by the dashboard at ``GET /``.

Deliberately dependency-free: no build chain, no external assets. The console
is a tabbed GUI (live operations, persisted scans with findings, and a report
browser). All state is fetched from the authenticated JSON API; the operator
supplies their bearer token in the page, which is kept in memory only.
"""

OPERATOR_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetworkForgeAI Operator Console</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; background:#14181d; color:#e6e6e6; }
  h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin-top: 2rem; }
  table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
  th, td { border: 1px solid #333; padding: .4rem .5rem; text-align: left; font-size: .9rem; }
  th { background: #1e242b; }
  button { cursor: pointer; border: none; border-radius: 4px; padding: .35rem .7rem; margin-right: .3rem; font-size: .85rem; }
  .approve { background: #2e7d32; color: #fff; } .reject { background: #c62828; color: #fff; }
  .warn { background: #ef6c00; color: #fff; }
  input { background:#1e242b; color:#e6e6e6; border:1px solid #444; padding:.3rem .5rem; border-radius:4px; width: 22rem; }
  .status-critical { color: #ff8a80; font-weight: bold; } .status-high { color: #ffb74d; font-weight: bold; }
  .status-medium { color: #ffe082; } .muted { color: #9aa0a6; }
  section { margin-bottom: 1rem; }
  nav.tabs { border-bottom: 1px solid #333; margin: 1.5rem 0 1rem; }
  nav.tabs button { background: transparent; color: #9aa0a6; border-radius: 4px 4px 0 0; padding: .5rem 1rem; }
  nav.tabs button.active { color: #e6e6e6; border-bottom: 2px solid #4a90d9; }
  .tabpanel { display: none; } .tabpanel.active { display: block; }
  pre.report { background: #10141a; border: 1px solid #333; border-radius: 4px; padding: .8rem; overflow-x: auto; white-space: pre-wrap; }
  tr.clickable { cursor: pointer; } tr.clickable:hover td { background: #1e242b; }
  #findingspane h3 { margin-bottom: .2rem; }
</style>
</head>
<body>
<h1>NetworkForgeAI Operator Console</h1>

<section id="auth">
  <label>Bearer token: <input type="password" id="token" placeholder="DASHBOARD_AUTH_TOKEN"></label>
  <button onclick="refreshAll()">Connect / Refresh</button>
  <span id="conn" class="muted">disconnected</span>
</section>

<nav class="tabs">
  <button id="tabbtn-live" class="active" onclick="switchTab('live')">Live</button>
  <button id="tabbtn-scans" onclick="switchTab('scans')">Scans &amp; findings</button>
  <button id="tabbtn-reports" onclick="switchTab('reports')">Reports</button>
</nav>

<div id="tabpanel-live" class="tabpanel active">
<section>
  <h2>Scan steering</h2>
  <button class="warn" onclick="steer('pause')">Pause</button>
  <button class="warn" onclick="steer('resume')">Resume</button>
  <button class="reject" onclick="if(confirm('Emergency stop: cancel pending approvals and halt?')) steer('stop')">Stop scan</button>
  <span id="scanstate" class="muted"></span>
</section>

<h2>Agent graph</h2>
<div class="muted">Live view of agents attached to the active scan.</div>
<svg id="agentgraph" width="100%" height="260" viewBox="0 0 600 260" role="img" aria-label="Agent graph"></svg>

<h2>Agent status</h2>
<table id="agents"><thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Capabilities</th></tr></thead><tbody></tbody></table>

<h2>Approval queue</h2>
<div class="muted">All exploitation actions require explicit approval. Approve only what your authorization covers.</div>
<table id="approvals"><thead><tr><th>Action</th><th>Target</th><th>Risk</th><th>Description</th><th></th></tr></thead><tbody></tbody></table>
</div>

<div id="tabpanel-scans" class="tabpanel">
<h2>Recent scans</h2>
<div class="muted">Click a scan to load its persisted findings.</div>
<table id="scans"><thead><tr><th>Scan ID</th><th>Status</th><th>Target</th><th>Findings</th></tr></thead><tbody></tbody></table>

<div id="findingspane">
  <h3 id="findingsheading">Findings</h3>
  <table id="findings">
    <thead><tr><th>Type</th><th>Title</th><th>Severity</th><th>Target</th><th>Status</th><th>Remediation</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
</div>

<div id="tabpanel-reports" class="tabpanel">
<h2>Reports</h2>
<div class="muted">Generated report files for the configured output directory. Click to view.</div>
<table id="reports"><thead><tr><th>Report path</th></tr></thead><tbody></tbody></table>
<pre id="reportview" class="report" hidden></pre>
</div>

<script>
const $ = (id) => document.getElementById(id);
const headers = () => ({ "Authorization": "Bearer " + $("token").value });

async function api(path, options) {
  const response = await fetch(path, { headers: headers(), ...options });
  if (!response.ok) throw new Error(response.status + " " + path);
  return response.json();
}

function setConn(ok, message) {
  const el = $("conn");
  el.textContent = message;
  el.className = ok ? "status-approved" : "status-high";
}

async function refreshAll() {
  try {
    const [agents, approvals] = await Promise.all([api("/agents"), api("/approvals")]);
    setConn(true, "connected to scan " + agents.scan_id);
    $("scanstate").textContent = "scan status: " + agents.scan_status;
    renderAgents(agents);
    renderApprovals(approvals);
    const scans = await api("/scans");
    renderScans(scans.scans || []);
  } catch (err) {
    setConn(false, "error: " + err.message + " (check token / live scan)");
  }
}

function switchTab(name) {
  for (const panel of document.getElementsByClassName("tabpanel")) {
    panel.classList.remove("active");
  }
  for (const btn of document.querySelectorAll("nav.tabs button")) {
    btn.classList.remove("active");
  }
  const panel = $("tabpanel-" + name), btn = $("tabbtn-" + name);
  if (panel) panel.classList.add("active");
  if (btn) btn.classList.add("active");
  if (name === "reports") loadReports();
}

const STATUS_COLORS = {
  idle: "#9aa0a6",
  working: "#66bb6a",
  running: "#66bb6a",
  waiting: "#ffb74d",
  stopped: "#ef5350",
};

function renderAgentGraph(agents) {
  const svg = $("agentgraph");
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  const NS = "http://www.w3.org/2000/svg";
  const cx = 300, cy = 130, rx = 220, ry = 90;
  const scan = document.createElementNS(NS, "circle");
  scan.setAttribute("cx", cx); scan.setAttribute("cy", cy);
  scan.setAttribute("r", 34);
  scan.setAttribute("fill", "#1e242b"); scan.setAttribute("stroke", "#4a90d9");
  scan.setAttribute("stroke-width", "2");
  const scanText = document.createElementNS(NS, "text");
  scanText.setAttribute("x", cx); scanText.setAttribute("y", cy + 5);
  scanText.setAttribute("text-anchor", "middle");
  scanText.setAttribute("fill", "#e6e6e6"); scanText.textContent = "scan";
  svg.append(scan, scanText);
  agents.forEach((agent, i) => {
    const angle = (2 * Math.PI * i) / Math.max(agents.length, 1) - Math.PI / 2;
    const x = cx + rx * Math.cos(angle), y = cy + ry * Math.sin(angle);
    const color = STATUS_COLORS[(agent.status || "").toLowerCase()] || "#9aa0a6";
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", cx); line.setAttribute("y1", cy);
    line.setAttribute("x2", x); line.setAttribute("y2", y);
    line.setAttribute("stroke", "#333"); line.setAttribute("stroke-width", "1.5");
    const node = document.createElementNS(NS, "circle");
    node.setAttribute("cx", x); node.setAttribute("cy", y); node.setAttribute("r", 14);
    node.setAttribute("fill", color);
    const title = document.createElementNS(NS, "title");
    title.textContent = agent.name + " [" + agent.status + "] " +
      (agent.capabilities || []).join(", ");
    node.appendChild(title);
    const label = document.createElementNS(NS, "text");
    label.setAttribute("x", x); label.setAttribute("y", y + 30);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("fill", "#e6e6e6");
    label.textContent = agent.name;
    svg.append(line, node, title, label);
  });
}

function renderAgents(payload) {
  renderAgentGraph(payload.agents);
  const tbody = $("agents").tBodies[0];
  tbody.innerHTML = "";
  for (const row of payload.agents) {
    tbody.insertAdjacentHTML("beforeend",
      `<tr><td>${esc(row.id.slice(0,8))}</td><td>${esc(row.name)}</td>` +
      `<td class="${row.status === 'running' ? 'status-medium' : ''}">${esc(row.status)}</td>` +
      `<td>${esc((row.capabilities || []).join(", "))}</td></tr>`);
  }
}

function renderApprovals(payload) {
  const tbody = $("approvals").tBodies[0];
  tbody.innerHTML = "";
  if (payload.emergency_stop) {
    tbody.insertAdjacentHTML("beforeend", "<tr><td colspan='5' class='status-high'>EMERGENCY STOP ACTIVE - new requests blocked</td></tr>");
  }
  for (const req of payload.pending) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(req.action_type)}</td><td>${esc(req.target)}</td>` +
      `<td class="status-${esc(req.risk_level)}">${esc(req.risk_level.toUpperCase())}</td>` +
      `<td>${esc(req.description)}</td>`;
    const actions = document.createElement("td");
    const approve = mkBtn("Approve", "approve", () => decide(req.id, "approve"));
    const reject = mkBtn("Reject", "reject", () => decide(req.id, "reject"));
    actions.append(approve, reject);
    tr.appendChild(actions);
    tbody.appendChild(tr);
  }
  if (!payload.pending.length && !payload.emergency_stop) {
    tbody.insertAdjacentHTML("beforeend", "<tr><td colspan='5' class='muted'>No pending approvals</td></tr>");
  }
}

function renderScans(scans) {
  const tbody = $("scans").tBodies[0];
  tbody.innerHTML = "";
  for (const s of scans) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    tr.innerHTML = `<td>${esc(s.scan_id)}</td><td>${esc(s.status)}</td>` +
      `<td>${esc(s.target || "")}</td><td>${s.finding_count}</td>`;
    tr.addEventListener("click", () => loadFindings(s.scan_id));
    tbody.appendChild(tr);
  }
  if (!scans.length) {
    tbody.insertAdjacentHTML("beforeend",
      "<tr><td colspan='4' class='muted'>No persisted scans found</td></tr>");
  }
}

async function loadFindings(scanId) {
  try {
    const payload = await api(`/scans/${encodeURIComponent(scanId)}/findings`);
    $("findingsheading").textContent =
      `Findings — ${scanId.slice(0, 8)} (${payload.count})`;
    const tbody = $("findings").tBodies[0];
    tbody.innerHTML = "";
    for (const f of payload.findings || []) {
      tbody.insertAdjacentHTML("beforeend",
        `<tr><td>${esc(f.type)}</td><td>${esc(f.title || "")}</td>` +
        `<td class="status-${esc(f.severity)}">${esc(f.severity)}</td>` +
        `<td>${esc(f.target)}</td><td>${esc(f.status || "")}</td>` +
        `<td>${esc(f.remediation || "")}</td></tr>`);
    }
    if (!payload.count) {
      tbody.insertAdjacentHTML("beforeend",
        "<tr><td colspan='6' class='muted'>No findings recorded</td></tr>");
    }
  } catch (err) {
    alert("Failed to load findings: " + err.message);
  }
}

async function loadReports() {
  try {
    const payload = await api("/reports");
    const tbody = $("reports").tBodies[0];
    tbody.innerHTML = "";
    $("reportview").hidden = true;
    for (const path of payload.reports || []) {
      const tr = document.createElement("tr");
      tr.className = "clickable";
      tr.innerHTML = `<td>${esc(path)}</td>`;
      tr.addEventListener("click", () => showReport(path));
      tbody.appendChild(tr);
    }
    if (!(payload.reports || []).length) {
      tbody.insertAdjacentHTML("beforeend",
        "<tr><td class='muted'>No reports available</td></tr>");
    }
  } catch (err) {
    alert("Failed to load reports: " + err.message);
  }
}

async function showReport(path) {
  try {
    const payload = await api(`/reports/${path.split("/").map(encodeURIComponent).join("/")}`);
    const view = $("reportview");
    view.hidden = false;
    const content = typeof payload.content === "string"
      ? payload.content
      : JSON.stringify(payload.content, null, 2);
    view.textContent = `# ${path}\n\n${content}`;
  } catch (err) {
    alert("Failed to load report: " + err.message);
  }
}

function esc(value) {
  const div = document.createElement("div");
  div.textContent = String(value ?? "");
  return div.innerHTML;
}

function mkBtn(label, cls, handler) {
  const btn = document.createElement("button");
  btn.textContent = label;
  btn.className = cls;
  btn.addEventListener("click", handler);
  return btn;
}

async function decide(requestId, decision) {
  try {
    await api(`/approvals/${requestId}/${decision}`, { method: "POST" });
  } catch (err) {
    alert("Decision failed: " + err.message);
  }
  refreshAll();
}

async function steer(action) {
  try {
    const result = await api(`/scan/${action}`, { method: "POST" });
    $("scanstate").textContent = "scan status: " + result.status;
  } catch (err) {
    alert("Steering failed: " + err.message);
  }
  refreshAll();
}
</script>
</body>
</html>
"""
