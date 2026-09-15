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
  nav.replaceChildren(...views.filter((v) => !v.hidden).map((v) =>
    el("a", { href: "#" + v.route, class: v.route === active ? "on" : "" }, v.title)));
}

/** route renders whichever view the fragment names, defaulting to the first. */
async function route() {
  // "#node/gpu-01" is the view and its argument. The fragment rather than a
  // path, so the console routes itself and the server serves one shell — there
  // is no second place that has to agree about which screens exist.
  const fragment = (window.location.hash || "").replace(/^#/, "") || views[0].route;
  const cut = fragment.indexOf("/");
  const name = cut < 0 ? fragment : fragment.slice(0, cut);
  const arg = cut < 0 ? "" : decodeURIComponent(fragment.slice(cut + 1));
  const view = views.find((v) => v.route === name) || views[0];
  tabs(view.route);
  show(el("p", { class: "empty" }, "Loading…"));
  try {
    await view.render(arg);
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
 *  that will not come back on its own is a different machine to plan around.
 *
 *  03 §7's two cases, and they are different machines. `manual-console` needs
 *  somebody at the physical console to unlock a disk. `host-managed` is WSL2,
 *  where a reboot inside the distribution does not restart Windows at all —
 *  and whether that node comes back turns on a scheduled task in the Windows
 *  scheduler, which is the other half §7 asks to be displayed.
 */
function rebootPolicy(node) {
  if (node.reboot_policy === "manual-console") return pill("manual-console", "warn");
  if (node.reboot_policy !== "host-managed") {
    return el("span", { class: "dim" }, node.reboot_policy || "—");
  }
  const logon = {
    present: ["starts at logon", "ok"],
    absent: ["no logon task", "bad"],
    unknown: ["logon task unknown", "warn"],
  }[node.logon_task];
  if (!logon) return pill("host-managed", "");
  return el("span", {}, pill("host-managed", ""), " ", pill(logon[0], logon[1]));
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

// --- R7-03: one node, its deployments, and how its cards are connected ----

/** deploymentState reads a deployment the way an operator does: `stopped` on a
 *  disabled one is a decision, on anything else it is a fault. */
function deploymentState(d) {
  if (d.disabled) return pill("stopped · disabled", "warn");
  switch (d.state) {
    case "ready":
      return pill(d.health === "healthy" ? "ready" : "ready · " + d.health,
        d.health === "healthy" ? "ok" : "warn");
    case "failed": return pill("failed", "bad");
    case "stopped": return pill("stopped", "warn");
    default: return pill(d.state, "warn");
  }
}

/** egress renders 03 §5's verdict. `inconclusive` is deliberately not "fine":
 *  a deployment that could not be shown to be isolated is not one that was. */
function egress(d) {
  if (!d.egress) return el("span", { class: "dim" }, "never run");
  if (d.egress === "compliant") return pill("isolated", "ok");
  if (d.egress === "non-compliant") return pill("has a way off the box", "bad");
  return pill(d.egress, "warn");
}

/** topology renders the connection matrix, which is why an index set is
 *  sensible or not. Absent on a one-card host, which is not a fault. */
function topology(node) {
  const t = node.topology || {};
  if (!t.matrix || !t.matrix.length) return null;
  const head = el("tr", {}, el("th", {}, ""), t.gpus.map((g) => el("th", {}, g)));
  const rows = t.matrix.map((row, i) => el("tr", {},
    el("th", {}, t.gpus[i]),
    row.map((cell, j) => {
      // Self is not a link, and a bonded NVLink is the pairing worth seeing.
      const kind = cell.startsWith("NV") ? "ok" : "";
      return el("td", {}, i === j ? el("span", { class: "dim" }, "—") : pill(cell, kind));
    })));
  return el("div", {},
    el("h2", {}, "How the cards reach each other"),
    el("p", { class: "note" }, `From \`${t.source}\`. `
      + "Two cards on the same NVLink behave nothing like two that reach each other across "
      + "the host bridge — an index set spanning the second pair runs a tensor-parallel "
      + "deployment slowly for no visible reason."),
    el("table", {}, el("thead", {}, head), el("tbody", {}, rows)));
}

views.push({
  route: "node",
  title: "Node",
  hidden: true,
  async render(name) {
    if (!name) {
      const doc = await api("/nodes");
      const first = (doc.nodes || [])[0];
      if (!first) return show(el("p", { class: "empty" }, "No node has enrolled yet."));
      window.location.hash = "#node/" + encodeURIComponent(first.name);
      return;
    }
    const node = await api("/nodes/" + encodeURIComponent(name));

    const deployments = (node.deployments || []).map((d) => el("tr", {},
      el("td", {}, d.state === "failed"
        ? el("a", { href: "#logs/" + encodeURIComponent(d.id) }, d.id)
        : d.id),
      el("td", {}, d.model_id),
      el("td", {}, deploymentState(d)),
      el("td", { class: "num" }, (d.gpus || []).join(", ") || "—"),
      el("td", {}, egress(d)),
      el("td", {}, (d.routes || []).join(", ") || el("span", { class: "dim" }, "no route")),
      el("td", { class: "dim" }, since(d.updated_at))));

    show(
      el("h1", {}, node.name, " ", nodeState(node)),
      el("p", { class: "note" },
        `${node.os}/${node.arch}`,
        node.driver_version ? ` · driver ${node.driver_version}` : "",
        node.agent_version ? ` · agent ${node.agent_version}` : "",
        ` · seen ${since(node.last_seen)} · `,
        rebootPolicy(node)),

      node.reboot_policy === "host-managed" && node.logon_task === "absent"
        ? el("p", { class: "problem" },
            "No scheduled task starts this distribution at logon. A Windows reboot leaves this "
            + "node stale until somebody opens a shell — which looks identical to any other "
            + "unreachable node and is fixed in thirty seconds by whoever knows that is what "
            + "happened.")
        : null,
      node.reboot_policy === "manual-console"
        ? el("p", { class: "problem" },
            "This host needs somebody at the physical console to come back up: its root "
            + "filesystem is encrypted with no automatic unlock. The agent will not reboot it.")
        : null,

      el("h2", {}, "Deployments"),
      table(["Deployment", "Model", "State", "GPUs", "Egress", "Routes", "Updated"],
        deployments, "Nothing is placed on this node."),
      topology(node));
  },
});

// --- R7-04: the catalog, and what is staged where --------------------------

/** bytes is a size a person reads rather than a number they count digits in. */
function bytes(n) {
  if (!n) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n < 10 && i ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

/** staged renders 05 §3's progress. `corrupt` is terminal and coloured as the
 *  fault it is: restaging is an operator's decision, not something that
 *  happens on its own. */
function staged(s) {
  if (s.state === "staged") return pill("staged", "ok");
  if (s.state === "corrupt") return pill("corrupt", "bad");
  if (s.state === "staging" || s.state === "verifying") {
    const done = s.bytes_total ? Math.floor((s.bytes_done / s.bytes_total) * 100) : 0;
    return pill(`${s.state} ${done}%`, "warn");
  }
  return pill(s.state || "absent", "");
}

views.push({
  route: "catalog",
  title: "Catalog",
  async render() {
    const [models, fleet] = await Promise.all([api("/models"), api("/nodes")]);
    // Staging lives against a node, so the catalog asks every node what it
    // holds. One request per node rather than a join the API does not offer —
    // and the fleet this is sold into is tens of machines, not thousands.
    const details = await Promise.all((fleet.nodes || [])
      .map((n) => api("/nodes/" + encodeURIComponent(n.name))));

    const byModel = new Map();
    for (const node of details) {
      for (const s of node.staging || []) {
        if (!byModel.has(s.model_id)) byModel.set(s.model_id, []);
        byModel.get(s.model_id).push({ node: node.name, ...s });
      }
    }

    const rows = (models.models || []).map((m) => {
      const where = byModel.get(m.id) || [];
      return el("tr", {},
        el("td", {}, m.id),
        el("td", { class: "dim" }, m.backend),
        el("td", { class: "dim" }, m.source),
        el("td", { class: "num" }, bytes(m.total_bytes)),
        el("td", {}, where.length
          ? where.map((s) => el("div", {}, staged(s), " ",
              el("span", { class: "dim" }, s.node),
              s.error ? el("div", { class: "note" }, s.error) : null))
          : el("span", { class: "dim" }, "nowhere")));
    });

    show(
      el("h2", {}, "Models"),
      table(["Model", "Backend", "Source", "Size", "Staged"], rows,
        "No model is registered. `nodary model register` places one."),
      (models.models || []).some((m) => m.origin_country)
        ? el("p", { class: "note" }, "Origin and licence are recorded per model in the configuration.")
        : null);
  },
});

// --- R7-05: usage ----------------------------------------------------------

views.push({
  route: "usage",
  title: "Usage",
  async render() {
    const group = window.sessionStorage.getItem("usage.group") || "model";
    const doc = await api("/usage?group_by=" + encodeURIComponent(group));
    const rows = (doc.usage || []).map((r) => el("tr", {},
      el("td", {}, r.subject || el("span", { class: "dim" }, "—")),
      el("td", { class: "num" }, r.requests.toLocaleString()),
      el("td", { class: "num" }, r.prompt_tokens.toLocaleString()),
      el("td", { class: "num" }, r.completion_tokens.toLocaleString())));

    const picker = el("select", {},
      ["model", "user", "node", "route"].map((g) =>
        el("option", { value: g, selected: g === group }, "by " + g)));
    picker.addEventListener("change", () => {
      window.sessionStorage.setItem("usage.group", picker.value);
      route();
    });

    show(
      el("h2", {}, "Usage ", picker),
      table(["Subject", "Requests", "Prompt tokens", "Completion tokens"], rows,
        "Nothing has been served yet."),
      // ADR 0006, said on the screen that reports requests: this is a count of
      // what happened, and there is nowhere for what was said.
      el("p", { class: "note" },
        "Counts only. nodary records that a request happened and never what it said — "
        + "the metering schema has no field to write a body into."));
  },
});

// --- R7-06: the audit browser ----------------------------------------------

views.push({
  route: "audit",
  title: "Audit",
  async render() {
    const filters = {
      actor: window.sessionStorage.getItem("audit.actor") || "",
      action: window.sessionStorage.getItem("audit.action") || "",
    };
    const query = Object.entries(filters)
      .filter(([, v]) => v)
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join("&");

    // The chain's verification status, shown rather than assumed. A browser
    // that displayed records without saying whether they still hash together
    // would be presenting an audit trail as trustworthy on no evidence, which
    // is the one thing this screen must not do.
    const [doc, verified] = await Promise.all([
      api("/audit" + (query ? "?" + query : "")),
      api("/audit/verify"),
    ]);

    const rows = (doc.audit || []).map((r) => el("tr", {},
      el("td", { class: "num dim" }, r.seq),
      el("td", { class: "dim" }, since(r.ts)),
      el("td", {}, r.actor && r.actor.id, el("span", { class: "dim" },
        r.actor && r.actor.method ? " · " + r.actor.method : "")),
      el("td", {}, el("code", {}, r.action)),
      el("td", {}, r.target ? `${r.target.kind}/${r.target.id}` : el("span", { class: "dim" }, "—")),
      el("td", {}, r.outcome === "ok" ? pill("ok", "ok") : pill(r.outcome || "?", "bad")),
      el("td", {}, r.justification || el("span", { class: "dim" }, "—"))));

    const inputs = ["actor", "action"].map((field) => {
      const box = el("input", { id: "f-" + field, value: filters[field], placeholder: field });
      box.addEventListener("change", () => {
        window.sessionStorage.setItem("audit." + field, box.value.trim());
        route();
      });
      return el("span", {}, box);
    });

    show(
      el("h2", {}, "Audit"),
      verified.ok
        ? el("p", {}, pill(`chain verified · ${verified.records} records`, "ok"))
        : el("p", { class: "problem" },
            "The chain does not verify: " + (verified.break || "a record does not follow the one before it")),
      el("div", { class: "filters" }, "Filter by ", ...inputs),
      table(["Seq", "When", "Actor", "Action", "Target", "Outcome", "Justification"], rows,
        "No record matches."),
      doc.next_cursor ? el("p", { class: "note" }, "Older records are not shown.") : null);
  },
});

// --- R7-08: what is not compliant, first-class -----------------------------
//
// Its own screen rather than a column somebody scrolls to. 11 §3 makes a
// failing egress assertion a critical alert, and 12 §1 makes a refusal the
// node's answer to a document it would not run — both are the kind of thing an
// operator has to go looking for in a CLI, and the whole point of a console is
// that they do not have to.

views.push({
  route: "attention",
  title: "Needs attention",
  async render() {
    const fleet = await api("/nodes");
    const details = await Promise.all((fleet.nodes || [])
      .map((n) => api("/nodes/" + encodeURIComponent(n.name))));

    const refusals = [];
    const leaking = [];
    const failed = [];
    for (const node of details) {
      for (const r of node.refusals || []) refusals.push({ node: node.name, ...r });
      for (const d of node.deployments || []) {
        if (d.egress && d.egress !== "compliant") leaking.push({ node: node.name, ...d });
        if (d.state === "failed") failed.push({ node: node.name, ...d });
      }
    }
    const pending = (fleet.nodes || []).filter((n) => n.state === "pending");

    const nothing = !refusals.length && !leaking.length && !failed.length && !pending.length;
    show(
      el("h2", {}, "Needs attention"),
      nothing ? el("p", {}, pill("nothing outstanding", "ok")) : null,

      leaking.length ? el("div", {},
        el("h2", {}, "Deployments that are not isolated"),
        el("p", { class: "note" },
          "03 §5 puts a deployment on a network with no route off the box, and the assertion "
          + "runs on the node after every start. `inconclusive` is not `compliant`: it means "
          + "nobody could show the control was in force."),
        table(["Node", "Deployment", "Egress", "Why"],
          leaking.map((d) => el("tr", {},
            el("td", {}, d.node), el("td", {}, d.id), el("td", {}, egress(d)),
            el("td", {}, d.egress_reason || el("span", { class: "dim" }, "—")))), "")) : null,

      refusals.length ? el("div", {},
        el("h2", {}, "Refused by a node"),
        el("p", { class: "note" },
          "`refused` means nothing started. `out_of_policy` means something is still serving "
          + "and the node will stop it in its maintenance window — they read alike and mean "
          + "opposite things."),
        table(["Node", "Deployment", "Kind", "Reason", "Since"],
          refusals.map((r) => el("tr", {},
            el("td", {}, r.node), el("td", {}, r.deployment_id),
            el("td", {}, r.kind === "out_of_policy" ? pill("out of policy", "warn") : pill("refused", "bad")),
            el("td", {}, r.reason), el("td", { class: "dim" }, since(r.updated_at)))), "")) : null,

      failed.length ? el("div", {},
        el("h2", {}, "Failed deployments"),
        table(["Node", "Deployment", "Model", "Since"],
          failed.map((d) => el("tr", {},
            el("td", {}, d.node),
            el("td", {}, el("a", { href: "#logs/" + encodeURIComponent(d.id) }, d.id)),
            el("td", {}, d.model_id), el("td", { class: "dim" }, since(d.updated_at)))), "")) : null,

      pending.length ? el("div", {},
        el("h2", {}, "Nodes awaiting approval"),
        table(["Node", "Seen"], pending.map((n) => el("tr", {},
          el("td", {}, el("a", { href: "#node/" + encodeURIComponent(n.name) }, n.name)),
          el("td", { class: "dim" }, since(n.last_seen)))), "")) : null);
  },
});

// --- the captured log of a failed deployment (R2-29's endpoint) ------------

views.push({
  route: "logs",
  title: "Log",
  hidden: true,
  async render(id) {
    if (!id) return show(el("p", { class: "empty" }, "No deployment named."));
    const doc = await api("/deployments/" + encodeURIComponent(id) + "/logs");
    show(
      el("h1", {}, doc.deployment),
      el("p", { class: "note" },
        `on ${doc.node} · ${doc.state} · captured ${since(doc.captured_at)}`),
      doc.lines
        ? el("pre", {}, doc.lines)
        : el("p", { class: "empty" },
            "Nothing is captured: the last hundred lines are taken when a deployment fails, "
            + "and this one has not."),
      el("p", { class: "note" },
        "What was captured when it failed, not a live tail — 00 §2 makes traffic to a node "
        + "agent-initiated, so the control plane has no channel to ask for one."));
  },
});
