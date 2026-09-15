// The read-only console (R7).
//
// **It is a third caller of the API, not a second implementation of it.** Every
// value on every screen comes from /api/v1 with the session cookie — the same
// endpoints `nodary --server` drives — so a field this page shows is a field the
// control plane computed. dev/tasks/README.md's cross-cutting constraint is that
// neither front end holds business logic; the way to keep that true of a browser
// is to give it no state of its own beyond what it last fetched.

const views = [];

/** api GETs a JSON endpoint, or sends the browser to the login page. */
async function api(path) {
  const response = await fetch("/api/v1" + path, { headers: { Accept: "application/json" } });
  if (response.status === 401) {
    window.location.assign("/ui/login");
    throw new Error("unauthenticated");
  }
  const doc = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error((doc.error && doc.error.message) || `${response.status}`);
  }
  return doc;
}

// --- rendering ------------------------------------------------------------
//
// Built from DOM nodes rather than by assembling HTML strings. The values here
// are node names, model ids, justifications and refusal reasons — text people
// typed — and textContent cannot be talked into being markup, which innerHTML
// can. It is the same decision internal/api/setup.go made by using
// html/template instead of text/template.

/** el builds an element: el("td", {class: "num"}, "12") */
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** pill is a state word, coloured by what it means rather than by its spelling. */
function pill(word, kind) {
  return el("span", { class: "pill " + (kind || "") }, word || "—");
}

/** table renders rows, or says plainly that there are none. */
function table(headings, rows, emptyMessage) {
  if (!rows.length) return el("p", { class: "empty" }, emptyMessage);
  return el("table", {},
    el("thead", {}, el("tr", {}, headings.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows));
}

function show(...nodes) {
  const view = document.getElementById("view");
  view.replaceChildren(...nodes);
}

function problem(err) {
  show(el("p", { class: "problem" }, String(err.message || err)));
}

// --- the shell ------------------------------------------------------------

/** header fills in who is signed in and which profile is in force. */
async function header() {
  const [me, policy] = await Promise.all([api("/auth/whoami"), api("/policy")]);
  document.getElementById("who").textContent = `${me.user} · ${me.role}`;
  const profile = document.getElementById("profile");
  profile.textContent = policy.name;
  profile.className = "profile " + (policy.name === "default" ? "" : policy.name);
  return { me, policy };
}

function tabs(active) {
  const nav = document.getElementById("tabs");
  nav.replaceChildren(...views.map((v) =>
    el("a", { href: "#" + v.route, class: v.route === active ? "on" : "" }, v.title)));
}

/** route renders whichever view the fragment names, defaulting to the first. */
async function route() {
  const name = (window.location.hash || "").replace(/^#/, "") || views[0].route;
  const view = views.find((v) => v.route === name) || views[0];
  tabs(view.route);
  show(el("p", { class: "empty" }, "Loading…"));
  try {
    await view.render();
  } catch (err) {
    if (err.message !== "unauthenticated") problem(err);
  }
}

document.getElementById("signout").addEventListener("click", async () => {
  await fetch("/api/v1/auth/logout", { method: "POST" }).catch(() => {});
  window.location.assign("/ui/login");
});

window.addEventListener("hashchange", route);

header()
  .then(route)
  .catch((err) => { if (err.message !== "unauthenticated") problem(err); });

// --- R7-02: the fleet -----------------------------------------------------

/** since is a timestamp rendered as an age, which is the question being asked. */
function since(stamp) {
  if (!stamp) return "never";
  const seconds = Math.round((Date.now() - Date.parse(stamp)) / 1000);
  if (!Number.isFinite(seconds)) return stamp;
  if (seconds < 90) return `${Math.max(seconds, 0)}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

/** nodeState colours a node by what its state means for an operator. */
function nodeState(node) {
  if (node.state === "pending") return pill("pending", "warn");
  if (node.incompatible) return pill("incompatible", "bad");
  if (node.stale) return pill(node.state + " · stale", "bad");
  if (node.state === "ready") return pill("ready", "ok");
  if (node.state === "departed") return pill("departed", "dim");
  return pill(node.state, "warn");
}

/** gpus counts what the driver found against what the node offered.
 *
 * Both, because the difference is the diagnostic fleet.Node's own comment
 * names: a node whose GPUs are present and whose offer is empty refused them,
 * which reads nothing like a node that has none.
 */
function gpus(node) {
  const present = (node.gpus || []).length;
  const offered = (node.offer && node.offer.gpus ? node.offer.gpus : []).length;
  if (!present) return el("span", { class: "dim" }, "none");
  if (offered === present) return el("span", {}, String(present));
  return el("span", {}, `${offered} of ${present} `,
    el("span", { class: "dim" }, "offered"));
}

/** rebootPolicy is displayed prominently because R7-02 asks for it: a node
 *  that will not come back on its own is a different machine to plan around. */
function rebootPolicy(node) {
  if (node.reboot_policy === "manual-console") return pill("manual-console", "warn");
  return el("span", { class: "dim" }, node.reboot_policy || "—");
}

views.push({
  route: "fleet",
  title: "Fleet",
  async render() {
    const doc = await api("/nodes");
    const nodes = doc.nodes || [];
    const rows = nodes.map((node) => el("tr", {},
      el("td", {}, el("a", { href: "#node/" + encodeURIComponent(node.name) }, node.name)),
      el("td", {}, nodeState(node)),
      el("td", { class: "num" }, gpus(node)),
      el("td", { class: "num" }, `${node.ready_count}/${node.deployment_count}`),
      el("td", {}, rebootPolicy(node)),
      el("td", {}, node.upgrade_error
        ? pill(node.agent_version + " · upgrade failed", "bad")
        : node.upgrade_target
          ? pill(`${node.agent_version} → ${node.upgrade_target}`, "warn")
          : el("span", { class: "dim" }, node.agent_version || "—")),
      el("td", { class: "dim" }, since(node.last_seen))));

    show(
      el("h2", {}, "Nodes"),
      table(["Node", "State", "GPUs", "Ready", "Reboot", "Agent", "Last seen"], rows,
        "No node has enrolled yet. `nodary node install` on a GPU host starts one."),
      nodes.some((n) => n.upgrade_error)
        ? el("p", { class: "problem" }, "A node failed to upgrade itself and is running what it had.")
        : null);
  },
});
