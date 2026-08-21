"""Single-file operator console served by the dashboard at ``GET /``.

Deliberately dependency-free: no build chain, no external assets. All state is
fetched from the authenticated JSON API; the operator supplies their bearer
token in the page, which is kept in memory only.
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
</style>
</head>
<body>
<h1>NetworkForgeAI Operator Console</h1>

<section id="auth">
  <label>Bearer token: <input type="password" id="token" placeholder="DASHBOARD_AUTH_TOKEN"></label>
  <button onclick="refreshAll()">Connect / Refresh</button>
  <span id="conn" class="muted">disconnected</span>
</section>

<section>
  <h2>Scan steering</h2>
  <button class="warn" onclick="steer('pause')">Pause</button>
  <button class="warn" onclick="steer('resume')">Resume</button>
  <button class="reject" onclick="if(confirm('Emergency stop: cancel pending approvals and halt?')) steer('stop')">Stop scan</button>
  <span id="scanstate" class="muted"></span>
</section>

<h2>Agent status</h2>
<table id="agents"><thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Capabilities</th></tr></thead><tbody></tbody></table>

<h2>Approval queue</h2>
<div class="muted">All exploitation actions require explicit approval. Approve only what your authorization covers.</div>
<table id="approvals"><thead><tr><th>Action</th><th>Target</th><th>Risk</th><th>Description</th><th></th></tr></thead><tbody></tbody></table>

<h2>Recent scans</h2>
<table id="scans"><thead><tr><th>Scan ID</th><th>Status</th><th>Target</th><th>Findings</th></tr></thead><tbody></tbody></table>

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

function renderAgents(payload) {
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
    tbody.insertAdjacentHTML("beforeend",
      `<tr><td>${esc(s.scan_id)}</td><td>${esc(s.status)}</td><td>${esc(s.target || "")}</td><td>${s.finding_count}</td></tr>`);
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
