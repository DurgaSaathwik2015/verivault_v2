
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtSize = n => n < 1024 ? n + " B" : n < 1048576 ? (n/1024).toFixed(1) + " KB" : (n/1048576).toFixed(1) + " MB";
const fmtDate = s => new Date(s.endsWith("Z") || s.includes("+") ? s : s + "Z").toLocaleString();
let me = null, cfg = {demo_mode:false}, docs = [], tab = "mine", authMode = "login";
let viewMode = localStorage.getItem("trustvault-doc-view") === "list" ? "list" : "grid";
const activeFilterFields = new Set();

async function api(path, opts = {}) {
  const o = {credentials: "same-origin", ...opts};
  if (o.json !== undefined) { o.method = o.method || "POST"; o.headers = {"Content-Type": "application/json"}; o.body = JSON.stringify(o.json); }
  try {
    const r = await fetch(path, o);
    let data = {}; try { data = await r.json(); } catch {}
    if (r.status === 401 && me) { me = null; document.querySelectorAll(".modal").forEach(m => m.remove()); showAuth(); }
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
  $("#t-login").setAttribute("aria-selected", String(m === "login")); $("#t-reg").setAttribute("aria-selected", String(m === "reg"));
  $("#f-reg").classList.toggle("hide", m === "login");
  $("#a-go").innerHTML = `${m === "login" ? "Sign in" : "Create account"} <span aria-hidden="true">&#8594;</span>`;
  $("#auth-kicker").textContent = m === "login" ? "WELCOME BACK" : "GET STARTED";
  $("#auth-title").textContent = m === "login" ? "Sign in to TrustVault" : "Create your account";
  $("#auth-subtitle").textContent = m === "login" ? "Your documents, shared with care." : "New accounts start with viewer access.";
  $("#a-pass").autocomplete = m === "login" ? "current-password" : "new-password";
  $("#a-err").textContent = "";
}
function openAuth(mode) {
  setAuthMode(mode);
  $("#auth-dialog").classList.remove("hide");
  requestAnimationFrame(() => (mode === "reg" ? $("#r-user") : $("#a-email")).focus());
}
function closeAuth() { $("#auth-dialog").classList.add("hide"); }
$("#t-login").onclick = () => setAuthMode("login"); $("#t-reg").onclick = () => setAuthMode("reg");
["public-login", "hero-login"].forEach(id => $("#" + id).onclick = () => openAuth("login"));
["public-register", "hero-register"].forEach(id => $("#" + id).onclick = () => openAuth("reg"));
$("#auth-close").onclick = closeAuth;
$("#auth-dialog").addEventListener("click", e => { if (e.target === $("#auth-dialog")) closeAuth(); });
$("#auth-dialog").addEventListener("keydown", e => {
  if (e.key === "Escape") { closeAuth(); return; }
  if (e.key !== "Tab") return;
  const fields = [...$("#auth-dialog").querySelectorAll("button:not([disabled]),input:not([disabled])")].filter(x => !x.closest(".hide"));
  const first = fields[0], last = fields[fields.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
});
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

function showAuth() { $("#app").classList.add("hide"); $("#auth").classList.remove("hide"); closeAuth(); setAuthMode("login"); }

async function boot() {
  $("#auth").classList.add("hide"); $("#app").classList.remove("hide");
  $("#me-name").textContent = me.username; $("#me-avatar").textContent = me.username.split(/\s+/).map(x => x[0]).join("").slice(0, 2).toUpperCase();
  const p = $("#me-role"); p.textContent = me.role; p.className = "pill " + me.role;
  document.querySelector('[data-tab="admin"]').classList.toggle("hide", me.role !== "admin");
  go(me.role === "admin" ? "admin" : me.role === "viewer" ? "shared" : "mine");
}
document.querySelectorAll("nav button").forEach(b => b.onclick = () => go(b.dataset.tab));
function go(t) {
  tab = t; document.querySelectorAll("nav button[data-tab]").forEach(b => { b.classList.toggle("on", b.dataset.tab === t); b.setAttribute("aria-current", b.dataset.tab === t ? "page" : "false"); });
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
  const v = $("#view");
  v.innerHTML = `<div class="skeleton" aria-hidden="true"></div><div class="skeleton" aria-hidden="true" style="margin-top:16px"></div>`;
  if (!await loadDocs()) return;
  const mine = tab === "mine", list = docs.filter(d => mine ? d.access === "owner" : d.access !== "owner");
  let h = "";
  if (mine && me.role === "owner") h += `<div class="drop" id="drop" role="button" tabindex="0" aria-label="Upload a document"><b>Drop a file here or browse</b><span class="meta">PDF, DOC, DOCX, TXT, PNG, JPG · up to 10 MB</span><span class="meta">Files are checked again by the server before upload.</span><input type="file" id="file" class="hide" accept=".pdf,.doc,.docx,.txt,.png,.jpg,.jpeg"><div class="progress hide" id="upload-progress" role="progressbar" aria-label="Upload progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><span style="width:0"></span></div></div>`;
  h += roleWelcome() + filterBar();
  h += `<div class="doc-heading"><div class="row"><h2>${mine ? "My documents" : "Shared with me"}</h2><span class="pill">${list.length}</span></div><div class="view-toggle" role="group" aria-label="Document display"><button id="grid-view" class="${viewMode === "grid" ? "on" : ""}" aria-label="Card view" title="Card view" aria-pressed="${viewMode === "grid"}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/></svg></button><button id="list-view" class="${viewMode === "list" ? "on" : ""}" aria-label="Table view" title="Table view" aria-pressed="${viewMode === "list"}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16M4 12h16M4 19h16"/></svg></button></div></div>`;
  if (!list.length) h += `<div class="empty"><b>${Object.values(filters).some(Boolean) ? "No matching documents" : mine ? "Your workspace is ready" : "Nothing has been shared with you yet"}</b><div class="meta">${Object.values(filters).some(Boolean) ? "Try adjusting the filters or clearing your search." : mine && me.role === "owner" ? "Upload a file to get started. It stays private until you choose to share it." : mine ? "Your role does not include ownership or upload access." : "When someone grants you access, shared files will appear here."}</div></div>`;
  else h += renderDocumentList(list, mine);
  v.innerHTML = h; wireDocs();
}
function safeGet(key) { try { return localStorage.getItem(key); } catch { return null; } }
function safeSet(key, value) { try { localStorage.setItem(key, value); } catch {} }
function roleWelcome() {
  const key = "trustvault-welcome-" + me.role;
  if (safeGet(key) === "dismissed") return "";
  const copy = {
    viewer: ["Your shared workspace", "Read or edit only the documents that have been shared with you."],
    owner: ["You’re in control", "Upload documents and grant or revoke access one file at a time."],
    admin: ["Oversight, not document access", "Review account and activity metadata. Document contents remain unavailable to admins by default."]
  }[me.role];
  return `<div class="banner role-banner"><div><b>${esc(copy[0])}</b><div class="meta">${esc(copy[1])}</div></div><button class="icon-btn" data-dismiss-welcome aria-label="Dismiss welcome message" title="Dismiss">&#10005;</button></div>`;
}
function fileIcon(filename) {
  const ext = (filename.split(".").pop() || "FILE").toUpperCase().slice(0, 4);
  return `<div class="ico" aria-label="${esc(ext)} file"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l5 5v13H6zM14 3v6h5M9 14h6M9 17h6"/></svg><span>${esc(ext)}</span></div>`;
}
function documentActions(d, mine) {
  const canEdit = d.access === "owner" || d.access === "edit";
  return `<div class="acts"><a class="btn sm" href="/documents/${d.id}/download">Download</a>${canEdit ? `<button class="btn sm" data-edit="${d.id}">Edit</button>` : ""}${mine ? `<button class="btn sm" data-share="${d.id}">Share</button><button class="btn sm bad" data-del="${d.id}">Delete</button>` : ""}</div>`;
}
function renderDocumentList(list, mine) {
  if (viewMode === "list") return `<div class="scroll"><table><thead><tr><th>Document</th><th>${mine ? "Category" : "Owner"}</th><th>Updated</th><th>Access</th><th>Actions</th></tr></thead><tbody>${list.map(d => `<tr><td><span class="table-file">${fileIcon(d.filename)}<b>${esc(d.filename)}</b></span></td><td>${esc(mine ? d.category || "Uncategorised" : d.owner || "Unknown")}</td><td>${fmtDate(d.created_at)}</td><td><span class="pill ${esc(d.access)}">${d.access === "owner" ? "Owner" : esc(d.access)}</span></td><td>${documentActions(d, mine)}</td></tr>`).join("")}</tbody></table></div>`;
  return `<div class="grid">${list.map(d => `<article class="doc"><div class="top">${fileIcon(d.filename)}<div class="doc-title"><div class="nm">${esc(d.filename)}</div><div class="meta"><span>${fmtSize(d.size)}</span><span aria-hidden="true">·</span><span>${esc(d.category || "Uncategorised")}</span></div></div></div><div class="meta"><span class="pill ${esc(d.access)}">${d.access === "owner" ? "Owner" : esc(d.access)}</span>${mine ? "" : `<span>Shared by ${esc(d.owner || "Unknown")}</span>`}<span>${fmtDate(d.created_at)}</span></div>${documentActions(d, mine)}</article>`).join("")}</div>`;
}
function filterBar() {
  const fields = [["owner", "Owner", "text", "Username"], ["category", "Category", "text", "Category"], ["date_from", "From date", "date", ""], ["date_to", "To date", "date", ""]];
  const chips = fields.map(([id, label]) => `<button class="chip ${activeFilterFields.has(id) ? "on" : ""}" type="button" data-filter="${id}" aria-pressed="${activeFilterFields.has(id)}">${label}</button>`).join("");
  const controls = fields.map(([id, label, type, placeholder]) => `<div class="filter-field ${activeFilterFields.has(id) ? "" : "hide"}" data-filter-field="${id}"><label for="f-${id}">${label}</label><input id="f-${id}" type="${type}" value="${esc(filters[id])}" placeholder="${placeholder}"></div>`).join("");
  return `<section class="filter-panel" aria-label="Search documents"><div class="search-row"><label class="hide" for="f-q">Search document names</label><input id="f-q" type="search" value="${esc(filters.q)}" placeholder="Search document names" aria-label="Search document names"><button class="btn pri" id="f-go">Search</button><button class="btn" id="f-clear">Clear</button></div><div class="filter-chip-row" aria-label="Add a filter">${chips}</div><div class="filter-extra">${controls}</div></section>`;
}
function wireFilters() {
  const apply = () => { filters.q = $("#f-q").value.trim(); for (const k of ["owner", "category", "date_from", "date_to"]) filters[k] = activeFilterFields.has(k) ? $("#f-" + k).value.trim() : ""; renderDocs(); };
  $("#f-go").onclick = apply;
  $("#f-clear").onclick = () => { for (const k in filters) filters[k] = ""; activeFilterFields.clear(); renderDocs(); };
  document.querySelectorAll("[data-filter]").forEach(b => b.onclick = () => {
    const key = b.dataset.filter, enabled = activeFilterFields.has(key);
    if (enabled) activeFilterFields.delete(key); else activeFilterFields.add(key);
    b.classList.toggle("on", !enabled); b.setAttribute("aria-pressed", String(!enabled));
    const field = document.querySelector(`[data-filter-field="${key}"]`); field.classList.toggle("hide", enabled);
    if (!enabled) field.querySelector("input").focus();
  });
  document.querySelectorAll(".filter-panel input").forEach(i => i.addEventListener("keydown", e => e.key === "Enter" && apply()));
}
function wireDocs() {
  wireFilters();
  const dismiss = $("[data-dismiss-welcome]");
  if (dismiss) dismiss.onclick = () => { safeSet("trustvault-welcome-" + me.role, "dismissed"); dismiss.closest(".banner").remove(); };
  const gridView = $("#grid-view"), listView = $("#list-view");
  if (gridView) gridView.onclick = () => { viewMode = "grid"; safeSet("trustvault-doc-view", viewMode); renderDocs(); };
  if (listView) listView.onclick = () => { viewMode = "list"; safeSet("trustvault-doc-view", viewMode); renderDocs(); };
  const upg = $("#upg"); if (upg) upg.onclick = async () => {
    const r = await api("/auth/demo-owner", {method: "POST"});
    if (r.ok) { me = r.data.user; boot(); toast("You can now upload documents"); } else toast(r.data.error || "Failed", true);
  };
  const drop = $("#drop"), file = $("#file");
  if (drop) {
    drop.onclick = () => file.click(); file.onchange = () => file.files[0] && upload(file.files[0]);
    drop.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); file.click(); } };
    ["dragenter", "dragover"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", ev => ev.dataTransfer.files[0] && upload(ev.dataTransfer.files[0]));
  }
  document.querySelectorAll("[data-edit]").forEach(b => b.onclick = () => editModal(+b.dataset.edit));
  document.querySelectorAll("[data-share]").forEach(b => b.onclick = () => shareModal(+b.dataset.share));
  document.querySelectorAll("[data-del]").forEach(b => b.onclick = () => delDoc(+b.dataset.del));
}
async function upload(f) {
  const allowed = new Set(["pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"]), ext = (f.name.split(".").pop() || "").toLowerCase();
  if (!allowed.has(ext)) { toast("Choose a PDF, DOC, DOCX, TXT, PNG, or JPG file.", true); return; }
  if (f.size > 10 * 1024 * 1024) { toast("Files must be 10 MB or smaller.", true); return; }
  const fd = new FormData(); fd.append("file", f);
  const progress = $("#upload-progress"), fill = progress.querySelector("span");
  progress.classList.remove("hide"); progress.setAttribute("aria-valuenow", "0"); fill.style.width = "0%";
  const xhr = new XMLHttpRequest(); xhr.open("POST", "/documents/upload"); xhr.withCredentials = true;
  xhr.upload.onprogress = e => { if (e.lengthComputable) { const value = Math.round(e.loaded / e.total * 100); progress.setAttribute("aria-valuenow", String(value)); fill.style.width = value + "%"; } };
  xhr.onload = () => {
    let data = {}; try { data = JSON.parse(xhr.responseText); } catch {}
    if (xhr.status === 401) { me = null; showAuth(); return; }
    xhr.status >= 200 && xhr.status < 300 ? toast("Uploaded " + (data.filename || f.name)) : toast(data.error || "Upload failed", true);
    renderDocs();
  };
  xhr.onerror = () => { toast("Network error. Upload failed.", true); renderDocs(); };
  xhr.send(fd);
}
async function delDoc(id) {
  const d = docs.find(x => x.id === id);
  const m = modal(`<h3>Delete document?</h3><p class="meta">“${esc(d.filename)}” will be permanently deleted and everyone’s access will be removed.</p><div class="row" style="justify-content:flex-end;margin-top:18px"><button class="btn" id="d-x">Cancel</button><button class="btn bad" id="d-ok">Delete permanently</button></div>`);
  m.querySelector("#d-x").onclick = () => closeModal(m);
  m.querySelector("#d-ok").onclick = async () => {
    const r = await api("/documents/" + id, {method: "DELETE"});
    if (r.ok) { closeModal(m); toast("Document deleted"); renderDocs(); }
    else toast(r.data.error || "Delete failed", true);
  };
}

/* ---------- modals ---------- */
function modal(html) {
  const m = document.createElement("div"); m.className = "modal"; m.returnFocus = document.activeElement;
  m.innerHTML = `<div class="card" role="dialog" aria-modal="true" tabindex="-1">${html}</div>`;
  const heading = m.querySelector("h3");
  if (heading) { heading.id = "modal-title"; m.querySelector(".card").setAttribute("aria-labelledby", heading.id); }
  else m.querySelector(".card").setAttribute("aria-label", "Dialog");
  m.addEventListener("click", e => { if (e.target === m) closeModal(m); });
  m.addEventListener("keydown", e => {
    if (e.key === "Escape") { closeModal(m); return; }
    if (e.key !== "Tab") return;
    const fields = [...m.querySelectorAll("button:not([disabled]),input:not([disabled]),select:not([disabled]),a[href]")].filter(x => !x.closest(".hide"));
    const first = fields[0], last = fields[fields.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
  document.body.append(m);
  requestAnimationFrame(() => (m.querySelector("input,select,button") || m.querySelector(".card")).focus());
  return m;
}
function closeModal(m) {
  const target = m.returnFocus;
  m.remove();
  if (target && target.isConnected) target.focus();
}
function editModal(id) {
  const d = docs.find(x => x.id === id);
  const m = modal(`<h3>Edit document</h3><label>File name</label><input id="e-name" value="${esc(d.filename)}"><label>Category</label><input id="e-cat" value="${esc(d.category || "")}" placeholder="e.g. Contracts">
    <div class="err" id="e-err"></div><div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" id="e-x">Cancel</button><button class="btn pri" id="e-ok">Save</button></div>`);
  m.querySelector("#e-x").onclick = () => closeModal(m);
  m.querySelector("#e-ok").onclick = async () => {
    const body = {filename: m.querySelector("#e-name").value}, cat = m.querySelector("#e-cat").value.trim();
    if (cat) body.category = cat;
    const r = await api("/documents/" + id, {method: "PATCH", json: body});
    if (!r.ok) return m.querySelector("#e-err").textContent = r.data.error || "Failed";
    closeModal(m); toast("Saved"); renderDocs();
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
  m.querySelector("#s-x").onclick = () => closeModal(m);
  const ur = await api("/users"), sel = m.querySelector("#s-user");
  const users = ur.data.users || [];
  if (!ur.ok) m.querySelector("#s-err").textContent = ur.data.error || "Cannot load users";
  sel.innerHTML = users.length ? users.map(u => `<option value="${u.id}">${esc(u.username)}</option>`).join("") : `<option value="">No other users yet</option>`;
  async function refresh() {
    const r = await api(`/documents/${id}/permissions`), box = m.querySelector("#s-list"), ps = r.data.permissions || [];
    box.innerHTML = ps.length ? ps.map(p => `<div class="grant"><b>${esc(p.username)}</b><span class="pill ${esc(p.permission)}">${esc(p.permission)}</span><button class="btn sm bad" data-rv="${p.user_id}" aria-label="Revoke ${esc(p.permission)} access for ${esc(p.username)}">Revoke</button></div>`).join("") : `<div class="meta">Only you have access.</div>`;
    box.querySelectorAll("[data-rv]").forEach(b => b.onclick = async () => {
      if (!b.dataset.confirm) { b.dataset.confirm = "true"; b.textContent = "Confirm revoke"; b.setAttribute("aria-label", "Confirm revoking this access"); return; }
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
  v.innerHTML = `<div class="skeleton" aria-hidden="true"></div><div class="skeleton" aria-hidden="true" style="margin-top:16px"></div>`;
  const r = await api("/audit" + (qs ? "?" + qs : ""));
  if (!r.ok) { if (r.status !== 401) toast(r.data.error || "Could not load activity", true); return; }
  const e = r.data.entries || [], isAdmin = r.data.scope === "all";
  const opt = (arr, cur) => `<option value="">All actions</option>` + arr.map(a => `<option value="${esc(a)}" ${a === cur ? "selected" : ""}>${esc(a.replaceAll("_", " "))}</option>`).join("");
  const outcomes = [["", "All outcomes"], ["success", "Success"], ["denied", "Denied"], ["failure", "Failure"]];
  const chart = auditChart(e);
  v.innerHTML = `<div class="row page-heading"><div><p class="eyebrow">AUDIT TRAIL</p><h2>Activity</h2></div><span class="pill">${isAdmin ? "All users" : "Your activity"}</span><div class="sp"></div><span class="chain ${r.data.chain_valid ? "ok" : "no"}" role="status">${r.data.chain_valid ? "Chain verified" : "Chain broken"}</span></div>
    <div class="meta audit-headline">Entries are hash-linked, including refused attempts. ${esc(r.data.head.entries)} total · head <code>${esc((r.data.head.hash || "").slice(0, 16) || "—")}</code></div>
    <section class="chart-wrap" aria-label="Seven day activity summary"><div class="chart-heading"><b>Last 7 days</b><span class="meta">From returned activity entries</span></div>${chart}</section>
    <div class="audit-controls"><label for="au-a">Action</label><select id="au-a">${opt(ACTIONS, auditF.action)}</select><div class="filter-chips" role="group" aria-label="Filter by outcome">${outcomes.map(([value, label]) => `<button class="chip ${auditF.outcome === value ? "on" : ""}" data-outcome="${value}" aria-pressed="${auditF.outcome === value}">${label}</button>`).join("")}</div></div>
    ${e.length ? `<div class="timeline">${e.map(x => `<article class="timeline-entry"><div class="meta"><time datetime="${esc(x.created_at)}">${fmtDate(x.created_at)}</time><span>·</span><span>#${esc(x.id)}</span></div><div><strong>${esc(x.action.replaceAll("_", " "))}</strong> <span class="o-${esc(x.outcome)}">${esc(x.outcome)}</span> <span class="meta">by ${esc(x.actor)}${x.document_id == null ? "" : ` · document ${esc(x.document_id)}`}</span></div>${isAdmin && x.details ? `<div class="meta audit-details">${esc(x.details)}</div>` : ""}<div class="meta audit-hash">Hash <code>${esc(x.hash)}</code></div></article>`).join("")}</div>` : `<div class="empty">No matching activity. Try another action or outcome.</div>`}`;
  $("#au-a").onchange = ev => { auditF.action = ev.target.value; renderAudit(); };
  v.querySelectorAll("[data-outcome]").forEach(b => b.onclick = () => { auditF.outcome = b.dataset.outcome; renderAudit(); });
}
function auditChart(entries) {
  const today = new Date(), days = [];
  for (let offset = 6; offset >= 0; offset--) {
    const date = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - offset));
    days.push({key: date.toISOString().slice(0, 10), label: date.toLocaleDateString(undefined, {weekday: "short", timeZone: "UTC"}), count: 0});
  }
  const byDay = new Map(days.map(day => [day.key, day]));
  entries.forEach(entry => {
    const date = new Date(entry.created_at);
    if (!Number.isNaN(date.valueOf())) { const day = byDay.get(date.toISOString().slice(0, 10)); if (day) day.count++; }
  });
  const max = Math.max(1, ...days.map(day => day.count)), baseline = 112, chartHeight = 82, step = 86, startX = 44;
  const grid = [0, .5, 1].map(f => `<line class="chart-grid" x1="32" y1="${baseline - chartHeight * f}" x2="630" y2="${baseline - chartHeight * f}"/>`).join("");
  const bars = days.map((day, i) => {
    const height = day.count ? Math.max(4, day.count / max * chartHeight) : 2, x = startX + i * step;
    return `<rect class="chart-bar" x="${x}" y="${baseline - height}" width="34" height="${height}" rx="4"><title>${day.label}: ${day.count} ${day.count === 1 ? "entry" : "entries"}</title></rect><text class="chart-label" x="${x + 17}" y="137" text-anchor="middle">${day.label}</text>`;
  }).join("");
  return `<svg viewBox="0 0 640 148" role="img" aria-label="Daily audit entries over the last seven days">${grid}${bars}</svg>`;
}

/* ---------- admin ---------- */
async function renderAdmin() {
  const v = $("#view"), [s, u, d] = await Promise.all([api("/admin/summary"), api("/admin/users"), api("/admin/documents")]);
  if (!s.ok) { if (s.status !== 401) v.innerHTML = `<div class="empty">Admin access required.</div>`; return; }
  const S = s.data, L = S.last_24h;
  const stat = (n, t) => `<div class="stat"><b>${n}</b><span>${t}</span></div>`;
  v.innerHTML = `${roleWelcome()}<div class="row page-heading"><div><p class="eyebrow">TRUST &amp; SAFETY</p><h2>Admin overview</h2></div><span class="pill admin">Admin</span></div>
    <div class="meta admin-description">Account and activity oversight only. Document contents are not available to admins by default.</div>
    <div class="stats">${stat(S.users, "users")}${stat(S.documents, "documents")}${stat(S.grants, "active grants")}${stat(L.downloads, "downloads (24h)")}${stat(L.permission_changes, "permission changes (24h)")}${stat(L.refused, "refused attempts (24h)")}${stat(L.failed_logins, "failed logins (24h)")}</div>
    <section class="alerts-panel"><h3 class="sec">Alerts</h3>${S.alerts.length ? S.alerts.map(a => `<div class="alert">${esc(a)}</div>`).join("") : `<div class="alert ok">No unusual activity reported in the last 24 hours.</div>`}</section>
    <h3 class="sec">Users</h3><div class="scroll"><table><tr><th>User</th><th>Email</th><th>Role</th><th>Docs</th><th>Status</th><th></th></tr>` +
    (u.data.users || []).map(x => `<tr><td>${esc(x.username)}</td><td>${esc(x.email)}</td><td>${x.id === me.id ? `<span class="pill ${x.role}">${x.role}</span>` : `<select data-role="${x.id}">${["viewer","owner","admin"].map(r => `<option ${r === x.role ? "selected" : ""}>${r}</option>`).join("")}</select>`}</td><td>${x.documents}</td><td>${x.is_active ? "active" : '<span class="o-failure">disabled</span>'}</td><td>${x.id === me.id ? "" : `<button class="btn sm ${x.is_active ? "bad" : ""}" data-toggle="${x.id}" data-to="${!x.is_active}">${x.is_active ? "Disable" : "Enable"}</button>`}</td></tr>`).join("") +
    `</table></div><h3 class="sec">All documents <span class="meta">(metadata only)</span></h3>` +
    ((d.data.documents || []).length ? `<div class="scroll"><table><tr><th>Name</th><th>Owner</th><th>Category</th><th>Shared with</th><th>Created</th></tr>` +
    d.data.documents.map(x => `<tr><td>${esc(x.filename)}</td><td>${esc(x.owner)}</td><td>${esc(x.category || "–")}</td><td>${x.shared_with.map(g => `${esc(g.username)} <span class="pill ${g.permission}">${g.permission}</span>`).join(" ") || "–"}</td><td>${fmtDate(x.created_at)}</td></tr>`).join("") + `</table></div>` : `<div class="empty" style="margin-top:12px">No documents.</div>`);
  const dismiss = v.querySelector("[data-dismiss-welcome]");
  if (dismiss) dismiss.onclick = () => { safeSet("trustvault-welcome-" + me.role, "dismissed"); dismiss.closest(".banner").remove(); };
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
  m.querySelector("#p-x").onclick = () => closeModal(m);
  m.querySelector("#p-ok").onclick = async () => {
    const r = await api("/auth/change-password", {json: {current_password: m.querySelector("#p-old").value, new_password: m.querySelector("#p-new").value}});
    if (!r.ok) return m.querySelector("#p-err").textContent = r.data.error || "Failed";
    closeModal(m); toast("Password changed; other sessions were signed out");
  };
};

(async () => {
  const c = await api("/config"); if (c.ok) cfg = c.data;
  const r = await api("/auth/me");
  r.ok ? (me = r.data.user, boot()) : showAuth();
})();
