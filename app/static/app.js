
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtSize = n => n < 1024 ? n + " B" : n < 1048576 ? (n/1024).toFixed(1) + " KB" : (n/1048576).toFixed(1) + " MB";
const fmtDate = s => new Date(s.endsWith("Z") || s.includes("+") ? s : s + "Z").toLocaleString();
let me = null, cfg = {demo_mode:false}, docs = [], tab = "mine", authMode = "login";

async function api(path, opts = {}) {
  const o = {credentials: "same-origin", ...opts};
  if (o.json !== undefined) { o.method = o.method || "POST"; o.headers = {"Content-Type": "application/json"}; o.body = JSON.stringify(o.json); }
  try {
    const r = await fetch(path, o);
    let data = {}; try { data = await r.json(); } catch {}
    return {ok: r.ok, status: r.status, data};
  } catch { return {ok: false, status: 0, data: {error: "Network error"}}; }
}
function toast(msg, bad) {
  const t = document.createElement("div"); t.className = "toast" + (bad ? " bad" : ""); t.textContent = msg;
  $("#toasts").append(t); setTimeout(() => t.remove(), 3500);
}

/* ---------- auth ---------- */
function setAuthMode(m) {
  authMode = m;
  $("#t-login").classList.toggle("on", m === "login"); $("#t-reg").classList.toggle("on", m === "reg");
  $("#f-reg").classList.toggle("hide", m === "login");
  $("#a-go").textContent = m === "login" ? "Sign in" : "Create account"; $("#a-err").textContent = "";
}
$("#t-login").onclick = () => setAuthMode("login"); $("#t-reg").onclick = () => setAuthMode("reg");
async function submitAuth() {
  const email = $("#a-email").value, password = $("#a-pass").value;
  $("#a-err").textContent = "";
  if (authMode === "reg") {
    const r = await api("/auth/register", {json: {username: $("#r-user").value, email, password}});
    if (!r.ok) return $("#a-err").textContent = r.data.error || "Registration failed";
    toast("Account created. Signing you in…");
  }
  const r = await api("/auth/login", {json: {email, password}});
  if (!r.ok) return $("#a-err").textContent = r.data.error || "Login failed";
  me = r.data.user; $("#a-pass").value = ""; boot();
}
$("#a-go").onclick = submitAuth;
["a-email", "a-pass", "r-user"].forEach(id => $("#" + id).addEventListener("keydown", e => e.key === "Enter" && submitAuth()));
$("#logout").onclick = async () => { await api("/auth/logout", {method: "POST"}); me = null; showAuth(); };

function showAuth() { $("#app").classList.add("hide"); $("#auth").classList.remove("hide"); setAuthMode("login"); }

async function boot() {
  $("#auth").classList.add("hide"); $("#app").classList.remove("hide");
  $("#me-name").textContent = me.username; const p = $("#me-role"); p.textContent = me.role; p.className = "pill " + me.role;
  document.querySelector('[data-tab="admin"]').classList.toggle("hide", me.role !== "admin");
  go("mine");
}
document.querySelectorAll("nav button").forEach(b => b.onclick = () => go(b.dataset.tab));
function go(t) {
  tab = t; document.querySelectorAll("nav button").forEach(b => b.classList.toggle("on", b.dataset.tab === t));
  t === "audit" ? renderAudit() : t === "admin" ? renderAdmin() : renderDocs();
}

/* ---------- documents ---------- */
const filters = {q: "", owner: "", category: "", date_from: "", date_to: ""};
async function loadDocs() {
  const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString();
  const r = await api("/documents" + (qs ? "?" + qs : ""));
  if (r.status === 401) { showAuth(); return false; }
  docs = r.data.documents || []; return true;
}
async function renderDocs() {
  const v = $("#view"); if (!await loadDocs()) return;
  const mine = tab === "mine", list = docs.filter(d => mine ? d.access === "owner" : d.access !== "owner");
  let h = "";
  if (mine) {
    if (me.role !== "owner") {
      h += `<div class="banner"><div style="flex:1"><b>Your account is a ${esc(me.role)}.</b><div class="meta">Only <b>owner</b> accounts can upload documents.${cfg.demo_mode ? "" : " Ask an admin to run: <code>flask --app run set-role " + esc(me.email) + " owner</code>"}</div></div>${cfg.demo_mode ? '<button class="btn pri" id="upg">Become an owner</button>' : ""}</div>`;
    } else {
      h += `<div class="drop" id="drop"><b>Drop a file here</b> or click to browse<div class="meta" style="justify-content:center;margin-top:6px">PDF, DOC(X), TXT, PNG, JPG · up to 10 MB · content is verified against the extension</div><input type="file" id="file" class="hide"></div>`;
    }
  }
  h += filterBar();
  h += `<div class="row" style="margin-top:14px"><h2>${mine ? "My documents" : "Shared with me"}</h2><span class="pill">${list.length}</span></div>`;
  if (!list.length) h += `<div class="empty" style="margin-top:18px">${Object.values(filters).some(Boolean) ? "No documents match your search." : mine ? "Nothing here yet." : "No one has shared a document with you yet."}</div>`;
  else h += `<div class="grid">` + list.map(d => {
    const ext = (d.filename.split(".").pop() || "").slice(0, 4).toUpperCase();
    const canEdit = d.access === "owner" || d.access === "edit";
    return `<div class="doc"><div class="top"><div class="ico">${esc(ext)}</div><div><div class="nm">${esc(d.filename)}</div>
      <div class="meta"><span>${fmtSize(d.size)}</span><span>·</span><span>${esc(d.category || "uncategorised")}</span></div></div></div>
      <div class="meta"><span class="pill ${d.access}">${d.access === "owner" ? "you own" : d.access}</span>${mine ? "" : "<span>from " + esc(d.owner) + "</span>"}<span>· ${fmtDate(d.created_at)}</span></div>
      <div class="acts"><a class="btn sm" href="/documents/${d.id}/download">Download</a>
      ${canEdit ? `<button class="btn sm" data-edit="${d.id}">Edit</button>` : ""}
      ${mine ? `<button class="btn sm" data-share="${d.id}">Share</button><button class="btn sm bad" data-del="${d.id}">Delete</button>` : ""}</div></div>`;
  }).join("") + `</div>`;
  v.innerHTML = h; wireDocs();
}
function filterBar() {
  const f = (id, label, type = "text", ph = "") => `<div><label>${label}</label><input id="f-${id}" type="${type}" value="${esc(filters[id])}" placeholder="${ph}"></div>`;
  return `<div class="filters">${f("q", "File name", "text", "search…")}${f("owner", "Owner", "text", "username")}${f("category", "Category")}${f("date_from", "From", "date")}${f("date_to", "To", "date")}<div class="inline"><button class="btn pri" id="f-go">Search</button><button class="btn" id="f-clear">Clear</button></div></div>`;
}
function wireFilters() {
  const apply = () => { for (const k in filters) filters[k] = $("#f-" + k).value.trim(); renderDocs(); };
  $("#f-go").onclick = apply; $("#f-clear").onclick = () => { for (const k in filters) filters[k] = ""; renderDocs(); };
  document.querySelectorAll(".filters input").forEach(i => i.addEventListener("keydown", e => e.key === "Enter" && apply()));
}
function wireDocs() {
  wireFilters();
  const upg = $("#upg"); if (upg) upg.onclick = async () => {
    const r = await api("/auth/demo-owner", {method: "POST"});
    if (r.ok) { me = r.data.user; boot(); toast("You can now upload documents"); } else toast(r.data.error || "Failed", true);
  };
  const drop = $("#drop"), file = $("#file");
  if (drop) {
    drop.onclick = () => file.click(); file.onchange = () => file.files[0] && upload(file.files[0]);
    ["dragenter", "dragover"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", ev => ev.dataTransfer.files[0] && upload(ev.dataTransfer.files[0]));
  }
  document.querySelectorAll("[data-edit]").forEach(b => b.onclick = () => editModal(+b.dataset.edit));
  document.querySelectorAll("[data-share]").forEach(b => b.onclick = () => shareModal(+b.dataset.share));
  document.querySelectorAll("[data-del]").forEach(b => b.onclick = () => delDoc(+b.dataset.del));
}
async function upload(f) {
  const fd = new FormData(); fd.append("file", f);
  const r = await api("/documents/upload", {method: "POST", body: fd});
  r.ok ? toast("Uploaded " + r.data.filename) : toast(r.data.error || "Upload failed", true); renderDocs();
}
async function delDoc(id) {
  const d = docs.find(x => x.id === id);
  if (!confirm(`Delete "${d.filename}" permanently? This also revokes everyone's access.`)) return;
  const r = await api("/documents/" + id, {method: "DELETE"});
  r.ok ? toast("Document deleted") : toast(r.data.error || "Delete failed", true); renderDocs();
}

/* ---------- modals ---------- */
function modal(html) {
  const m = document.createElement("div"); m.className = "modal"; m.innerHTML = `<div class="card">${html}</div>`;
  m.onclick = e => { if (e.target === m) m.remove(); }; document.body.append(m); return m;
}
function editModal(id) {
  const d = docs.find(x => x.id === id);
  const m = modal(`<h3>Edit document</h3><label>File name</label><input id="e-name" value="${esc(d.filename)}"><label>Category</label><input id="e-cat" value="${esc(d.category || "")}" placeholder="e.g. Contracts">
    <div class="err" id="e-err"></div><div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="e-x">Cancel</button><button class="btn pri" id="e-ok">Save</button></div>`);
  m.querySelector("#e-x").onclick = () => m.remove();
  m.querySelector("#e-ok").onclick = async () => {
    const body = {filename: m.querySelector("#e-name").value}, cat = m.querySelector("#e-cat").value.trim();
    if (cat) body.category = cat;
    const r = await api("/documents/" + id, {method: "PATCH", json: body});
    if (!r.ok) return m.querySelector("#e-err").textContent = r.data.error || "Failed";
    m.remove(); toast("Saved"); renderDocs();
  };
}
async function shareModal(id) {
  const d = docs.find(x => x.id === id);
  const m = modal(`<h3>Share “${esc(d.filename)}”</h3><div class="meta">Grants can be revoked at any time.</div>
    <label>User</label><select id="s-user"></select><label>Permission</label>
    <select id="s-perm"><option value="read">Can read</option><option value="edit">Can edit</option></select>
    <div class="err" id="s-err"></div><button class="btn pri" id="s-ok" style="width:100%">Grant access</button>
    <label style="margin-top:22px">People with access</label><div id="s-list"></div>
    <div class="row" style="justify-content:flex-end;margin-top:16px"><button class="btn" id="s-x">Close</button></div>`);
  m.querySelector("#s-x").onclick = () => m.remove();
  const ur = await api("/users"), sel = m.querySelector("#s-user");
  const users = ur.data.users || [];
  if (!ur.ok) m.querySelector("#s-err").textContent = ur.data.error || "Cannot load users";
  sel.innerHTML = users.length ? users.map(u => `<option value="${u.id}">${esc(u.username)}</option>`).join("") : `<option value="">No other users yet</option>`;
  async function refresh() {
    const r = await api(`/documents/${id}/permissions`), box = m.querySelector("#s-list"), ps = r.data.permissions || [];
    box.innerHTML = ps.length ? ps.map(p => `<div class="grant"><b style="flex:1">${esc(p.username)}</b><span class="pill ${p.permission}">${p.permission}</span><button class="btn sm bad" data-rv="${p.user_id}">Revoke</button></div>`).join("") : `<div class="meta">Only you.</div>`;
    box.querySelectorAll("[data-rv]").forEach(b => b.onclick = async () => {
      const rr = await api(`/documents/${id}/share/${b.dataset.rv}`, {method: "DELETE"});
      rr.ok ? toast("Access revoked") : toast(rr.data.error || "Failed", true); refresh();
    });
  }
  m.querySelector("#s-ok").onclick = async () => {
    if (!sel.value) return;
    const r = await api(`/documents/${id}/share`, {json: {user_id: +sel.value, permission: m.querySelector("#s-perm").value}});
    r.ok ? toast("Access granted") : m.querySelector("#s-err").textContent = r.data.error || "Failed"; refresh();
  };
  refresh();
}

/* ---------- audit ---------- */
const auditF = {action: "", outcome: ""};
const ACTIONS = ["upload","download","change","delete","grant","revoke","login","logout","register","password_change","user_admin_change"];
async function renderAudit() {
  const v = $("#view"), qs = new URLSearchParams(Object.entries(auditF).filter(([, x]) => x)).toString();
  const r = await api("/audit" + (qs ? "?" + qs : ""));
  if (r.status === 401) return showAuth();
  const e = r.data.entries || [], isAdmin = r.data.scope === "all";
  const opt = (arr, cur) => `<option value="">all</option>` + arr.map(a => `<option ${a === cur ? "selected" : ""}>${a}</option>`).join("");
  v.innerHTML = `<div class="row"><h2>Activity</h2><span class="pill">${isAdmin ? "all users" : "your activity"}</span><div class="sp"></div>
    <span class="chain ${r.data.chain_valid ? "ok" : "no"}">${r.data.chain_valid ? "✓ Audit chain verified" : "⚠ Audit chain broken"}</span></div>
    <div class="meta" style="margin-top:6px">Each entry is hash-linked to the one before it, including refused attempts. ${r.data.head.entries} entries · head <code>${esc((r.data.head.hash || "–").slice(0, 16))}</code></div>
    <div class="inline" style="margin-top:14px"><span class="meta">Action</span><select id="au-a">${opt(ACTIONS, auditF.action)}</select><span class="meta">Result</span><select id="au-o">${opt(["success","denied","failure"], auditF.outcome)}</select></div>
    ${e.length ? `<div class="scroll"><table><tr><th>#</th><th>When</th><th>Who</th><th>Action</th><th>Doc</th><th>Result</th>${isAdmin ? "<th>Details</th>" : ""}<th>Hash</th></tr>` +
    e.map(x => `<tr><td>${x.id}</td><td>${fmtDate(x.created_at)}</td><td>${esc(x.actor)}</td><td>${esc(x.action)}</td><td>${x.document_id ?? "–"}</td><td class="o-${esc(x.outcome)}">${esc(x.outcome)}</td>${isAdmin ? `<td><code>${esc(x.details || "")}</code></td>` : ""}<td><code>${esc(x.hash)}</code></td></tr>`).join("") + `</table></div>` : `<div class="empty" style="margin-top:18px">No matching activity.</div>`}`;
  $("#au-a").onchange = ev => { auditF.action = ev.target.value; renderAudit(); };
  $("#au-o").onchange = ev => { auditF.outcome = ev.target.value; renderAudit(); };
}

/* ---------- admin ---------- */
async function renderAdmin() {
  const v = $("#view"), [s, u, d] = await Promise.all([api("/admin/summary"), api("/admin/users"), api("/admin/documents")]);
  if (!s.ok) { v.innerHTML = `<div class="empty">Admin access required.</div>`; return; }
  const S = s.data, L = S.last_24h;
  const stat = (n, t) => `<div class="stat"><b>${n}</b><span>${t}</span></div>`;
  v.innerHTML = `<div class="row"><h2>Administration</h2><span class="pill admin">admin</span></div>
    <div class="meta" style="margin-top:6px">Admins manage accounts and oversee activity. They cannot open document contents unless an owner grants them access.</div>
    <div class="stats">${stat(S.users, "users")}${stat(S.documents, "documents")}${stat(S.grants, "active grants")}${stat(L.downloads, "downloads (24h)")}${stat(L.permission_changes, "permission changes (24h)")}${stat(L.refused, "refused attempts (24h)")}${stat(L.failed_logins, "failed logins (24h)")}</div>
    ${S.alerts.length ? S.alerts.map(a => `<div class="alert">⚠ ${esc(a)}</div>`).join("") : `<div class="alert ok">✓ Nothing unusual in the last 24 hours.</div>`}
    <h3 class="sec">Users</h3><div class="scroll"><table><tr><th>User</th><th>Email</th><th>Role</th><th>Docs</th><th>Status</th><th></th></tr>` +
    (u.data.users || []).map(x => `<tr><td>${esc(x.username)}</td><td>${esc(x.email)}</td><td>${x.id === me.id ? `<span class="pill ${x.role}">${x.role}</span>` : `<select data-role="${x.id}">${["viewer","owner","admin"].map(r => `<option ${r === x.role ? "selected" : ""}>${r}</option>`).join("")}</select>`}</td><td>${x.documents}</td><td>${x.is_active ? "active" : '<span class="o-failure">disabled</span>'}</td><td>${x.id === me.id ? "" : `<button class="btn sm ${x.is_active ? "bad" : ""}" data-toggle="${x.id}" data-to="${!x.is_active}">${x.is_active ? "Disable" : "Enable"}</button>`}</td></tr>`).join("") +
    `</table></div><h3 class="sec">All documents <span class="meta">(metadata only)</span></h3>` +
    ((d.data.documents || []).length ? `<div class="scroll"><table><tr><th>Name</th><th>Owner</th><th>Category</th><th>Shared with</th><th>Created</th></tr>` +
    d.data.documents.map(x => `<tr><td>${esc(x.filename)}</td><td>${esc(x.owner)}</td><td>${esc(x.category || "–")}</td><td>${x.shared_with.map(g => `${esc(g.username)} <span class="pill ${g.permission}">${g.permission}</span>`).join(" ") || "–"}</td><td>${fmtDate(x.created_at)}</td></tr>`).join("") + `</table></div>` : `<div class="empty" style="margin-top:12px">No documents.</div>`);
  v.querySelectorAll("[data-role]").forEach(sel => sel.onchange = async () => {
    const r = await api("/admin/users/" + sel.dataset.role, {method: "PATCH", json: {role: sel.value}});
    r.ok ? toast("Role updated") : toast(r.data.error || "Failed", true); renderAdmin();
  });
  v.querySelectorAll("[data-toggle]").forEach(b => b.onclick = async () => {
    const r = await api("/admin/users/" + b.dataset.toggle, {method: "PATCH", json: {is_active: b.dataset.to === "true"}});
    r.ok ? toast("Account updated; their sessions were ended") : toast(r.data.error || "Failed", true); renderAdmin();
  });
}

/* ---------- change password ---------- */
$("#pw").onclick = () => {
  const m = modal(`<h3>Change password</h3><label>Current password</label><input id="p-old" type="password" autocomplete="current-password"><label>New password</label><input id="p-new" type="password" autocomplete="new-password" placeholder="8–128 characters"><div class="err" id="p-err"></div><div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="p-x">Cancel</button><button class="btn pri" id="p-ok">Change</button></div>`);
  m.querySelector("#p-x").onclick = () => m.remove();
  m.querySelector("#p-ok").onclick = async () => {
    const r = await api("/auth/change-password", {json: {current_password: m.querySelector("#p-old").value, new_password: m.querySelector("#p-new").value}});
    if (!r.ok) return m.querySelector("#p-err").textContent = r.data.error || "Failed";
    m.remove(); toast("Password changed; other sessions were signed out");
  };
};

(async () => {
  const c = await api("/config"); if (c.ok) cfg = c.data;
  const r = await api("/auth/me");
  r.ok ? (me = r.data.user, boot()) : showAuth();
})();
