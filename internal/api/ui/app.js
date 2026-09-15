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
      el("td", { class: "dim" }, since(d.updated_at)),
      el("td", {}, restartButton(node, d))));

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

      nodeActions(node),

      el("h2", {}, "Deployments"),
      table(["Deployment", "Model", "State", "GPUs", "Egress", "Routes", "Updated", ""],
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
          : el("span", { class: "dim" }, "nowhere")),
        el("td", {}, modelActions(m, where)));
    });

    show(
      el("h2", {}, "Models"),
      table(["Model", "Backend", "Source", "Size", "Staged", ""], rows,
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

// --- R8: the attestation ceremony, in the browser --------------------------
//
// **One driver, and every mutation goes through it.** dev/specs/07-identity-audit.md §2
// is preview → intent_hash → justify → confirm, and the way to keep a third
// front end from inventing its own version is to give it exactly one that
// drives the same `?dry_run=true` endpoints an API client drives. A screen here
// describes *what* it wants done; none of them decides what ceremony costs.

/** send makes one attested request and reports what came back, refusals
 *  included — a refusal is an answer this flow acts on, not an exception. */
async function send(spec, opts) {
  const headers = { "Content-Type": "application/json" };
  if (opts.justification) headers["X-Nodary-Justify"] = opts.justification;
  if (opts.totp) headers["X-Nodary-TOTP"] = opts.totp;
  if (opts.intent) headers["X-Nodary-Intent"] = opts.intent;
  // 09 §2: the revision this screen read its object at. Sent only by an act
  // that read one first — there is nothing for a create to have raced with.
  if (spec.ifMatch) headers["If-Match"] = spec.ifMatch;

  const path = spec.path + (opts.dryRun
    ? (spec.path.includes("?") ? "&" : "?") + "dry_run=true"
    : "");
  const response = await fetch("/api/v1" + path, {
    method: spec.method || "POST",
    headers,
    body: spec.body === undefined ? "{}" : JSON.stringify(spec.body),
  });
  if (response.status === 401) {
    window.location.assign("/ui/login");
    throw new Error("unauthenticated");
  }
  const doc = await response.json().catch(() => ({}));
  const error = doc.error || {};
  return {
    ok: response.ok, status: response.status, doc,
    code: error.code || "", message: error.message || "",
  };
}

/** modal shows one step and resolves to the button that was pressed, or null
 *  if the operator backed out. Native <dialog>: no library, and Escape and the
 *  focus trap come from the platform rather than from code somebody maintains. */
function modal(title, nodes, buttons) {
  const box = document.getElementById("ceremony");
  const form = el("form", { method: "dialog" },
    el("h2", { style: "margin-top:0" }, title),
    ...nodes,
    el("div", { class: "row" }, buttons.map((b) =>
      el("button", { value: b.value, class: b.kind || "" }, b.label))));
  box.replaceChildren(form);
  box.showModal();
  return new Promise((resolve) => {
    box.addEventListener("close", () => resolve(box.returnValue || null), { once: true });
  });
}

/** changeLines renders what the control plane said it would do. It is the
 *  control plane's own rendering, never this page's reading of the request —
 *  what is approved has to be what the machine about to act described. */
function changeLines(change) {
  if (!change) return [el("p", { class: "note" }, "This act changes no configuration.")];
  const changes = change.changes;
  if (Array.isArray(changes) && changes.length) {
    return [el("ul", {}, changes.map((c) => el("li", {}, String(c))))];
  }
  if (Array.isArray(changes)) {
    return [el("p", { class: "note" }, "No change: the configuration already says this.")];
  }
  return [el("pre", {}, JSON.stringify(change, null, 2))];
}

/** act runs the whole ceremony for one mutation. Resolves true if it applied. */
async function act(spec) {
  let justification = "";
  let totp = "";
  let note = null;

  for (;;) {
    // 1. The justification. R8-02: the length the *profile* requires is
    //    enforced by the control plane, and this reports its refusal rather
    //    than second-guessing it — a minimum duplicated here is a second place
    //    that can disagree with the profile in force.
    const field = el("textarea", { id: "justify", rows: "3" });
    field.value = justification;
    const asked = await modal(spec.title, [
      note,
      spec.cost ? el("p", { class: "problem" }, spec.cost) : null,
      el("label", { for: "justify" }, "Why are you doing this?"),
      field,
    ].filter(Boolean), [
      { value: "", label: "Cancel" },
      { value: "go", label: "Preview", kind: "primary" },
    ]);
    if (asked !== "go") return false;
    justification = field.value.trim();
    note = null;

    // 2. The preview, rendered and hashed by the control plane.
    const preview = await send(spec, { dryRun: true, justification });
    if (!preview.ok) {
      note = el("p", { class: "problem" }, preview.message);
      continue;
    }

    // 3. What was previewed, and the hash that binds it.
    const confirmed = await modal(spec.title, [
      spec.cost ? el("p", { class: "problem" }, spec.cost) : null,
      el("p", { class: "note" }, "The control plane will apply:"),
      ...changeLines(preview.doc.change),
      el("p", { class: "note" }, "intent ", el("code", {}, preview.doc.intent_hash || "—")),
    ].filter(Boolean), [
      { value: "", label: "Cancel" },
      { value: "go", label: spec.verb || "Apply", kind: "primary" },
    ]);
    if (confirmed !== "go") return false;

    // 4. The act, carrying the hash that was on the screen.
    let done = await send(spec, { justification, totp, intent: preview.doc.intent_hash });

    // R8-03: a live session does not satisfy `require_totp`. A cookie proves
    // somebody logged in at some point; a re-entered code proves a person was
    // present for *this* act, which is the whole of what 07 §2 asks for.
    if (!done.ok && done.code === "reauthentication_required") {
      const code = el("input", { id: "totp", inputmode: "numeric", autocomplete: "one-time-code" });
      const gave = await modal(spec.title, [
        el("p", { class: "note" }, done.message),
        el("label", { for: "totp" }, "Authentication code"),
        code,
      ], [
        { value: "", label: "Cancel" },
        { value: "go", label: spec.verb || "Apply", kind: "primary" },
      ]);
      if (gave !== "go") return false;
      totp = code.value.trim();
      done = await send(spec, { justification, totp, intent: preview.doc.intent_hash });
    }

    if (done.ok) {
      await modal(spec.title, [
        el("p", {}, pill("applied", "ok"), " recorded as audit record ",
          el("code", {}, String(done.doc.audit_seq || "—"))),
      ], [{ value: "ok", label: "Close", kind: "primary" }]);
      route();
      return true;
    }

    // 5. The two refusals that are not mistakes, and read differently.
    //
    // 412: state moved between the preview and the apply, so what would be
    // applied is not what was approved. 11 §3 makes that a refusal rather than
    // an overwrite, and the operator re-reads the current diff and re-attests —
    // which is exactly what looping back to the preview does.
    if (done.status === 412) {
      note = el("p", { class: "problem" },
        "What would be applied is no longer what you approved — something moved while you "
        + "were reading. The preview below is the current one.");
      continue;
    }
    // 409 would_drop_the_model: 03 §7 refuses a roll that takes the last
    // replica down, and the refusal names the way out. Offered rather than
    // hidden — and the cost is stated in the operator's own terms before they
    // take it, which is R8-05.
    if (done.code === "would_drop_the_model" && spec.allowDowntime) {
      const accept = await modal(spec.title, [
        el("p", { class: "problem" }, done.message),
        el("p", { class: "note" },
          "Accepting the gap restarts the only replica that is serving. Requests to this "
          + "model are refused until it answers again, which for a large model is minutes."),
      ], [
        { value: "", label: "Cancel" },
        { value: "go", label: "Accept the gap", kind: "danger" },
      ]);
      if (accept !== "go") return false;
      spec = { ...spec, path: spec.allowDowntime, allowDowntime: null };
      continue;
    }
    // 409 revision_changed: another administrator applied a revision since this
    // screen read its object. A real conflict, surfaced rather than resolved by
    // silently overwriting them.
    if (done.code === "revision_changed") {
      await modal(spec.title, [
        el("p", { class: "problem" },
          "Another administrator changed the configuration while this screen was open. "
          + "Nothing was applied. Reload and look at what they did before acting."),
        el("p", { class: "note" }, done.message),
      ], [{ value: "ok", label: "Close" }]);
      return false;
    }
    note = el("p", { class: "problem" }, done.message || `refused with ${done.status}`);
  }
}

/** button is one act, wired to the ceremony. */
function button(label, spec, kind) {
  const b = el("button", { class: kind || "" }, label);
  b.addEventListener("click", () => act(spec));
  return b;
}

/** actions is a row of them. */
function actions(...nodes) {
  return el("div", { class: "row" }, nodes.filter(Boolean));
}


// --- R8-04: the node's own transitions ------------------------------------

/** nodeActions is 02 §2's approval and the two ways out of the fleet.
 *
 *  Each one names its cost before asking (R8-05), because these read alike on
 *  a screen and do not mean alike on a rack.
 */
function nodeActions(node) {
  const at = "/nodes/" + encodeURIComponent(node.name);
  return actions(
    node.state === "pending"
      ? button("Approve", {
          title: `Approve ${node.name}`, path: at + "/approve", verb: "Approve",
          cost: "Approving records the inventory this node offered as what you agreed to. "
            + "Deployments can be placed on it from the moment it is approved.",
        }, "primary")
      : null,
    node.state === "ready" || node.state === "approved"
      ? button("Drain", {
          title: `Drain ${node.name}`, path: at + "/drain", verb: "Drain",
          cost: "Draining takes this node's deployments out of their routes on the next "
            + "gateway sync. Anything it is serving stops being sent traffic.",
        })
      : null,
    node.state !== "departed"
      ? button("Revoke", {
          title: `Revoke ${node.name}`, path: at + "/revoke", verb: "Revoke",
          cost: "Revoking ends this node's certificate. It cannot report or receive desired "
            + "state again without enrolling from scratch, and whatever is running on it "
            + "keeps running with nobody watching.",
        }, "danger")
      : null);
}


// --- R8-04/R8-05: what can be done to a model -----------------------------

/** modelActions is dev/specs/05-catalog.md §4's on/off switch and R4-35's
 *  staging recovery.
 *
 *  **`unstage` states the restaging cost before asking**, which R8-05 names
 *  specifically: on a screen the two words differ by three letters, and on a
 *  slow link the difference is hours.
 */
function modelActions(model, staged) {
  const at = "/models/" + encodeURIComponent(model.id);
  const bytes_ = bytes(model.total_bytes);
  const corrupt = staged.some((s) => s.state === "corrupt");
  return actions(
    button("Disable", {
      title: `Disable ${model.id}`, path: at + "/disable", verb: "Disable",
      cost: "Every deployment of this model stops. The weights stay staged and the GPUs stay "
        + "claimed — disabling does not free a card, so one freed for something else is "
        + "still spoken for.",
    }),
    button("Enable", {
      title: `Enable ${model.id}`, path: at + "/enable", verb: "Enable",
    }),
    button("Restage", {
      title: `Restage ${model.id}`, path: at + "/restage", verb: "Restage",
      cost: corrupt
        ? `The weights verified badly and will be fetched again — ${bytes_}.`
        : `The weights are fetched and verified again — ${bytes_}.`,
    }),
    button("Unstage", {
      title: `Unstage ${model.id}`, path: at + "/unstage", verb: "Unstage",
      cost: `The weights are deleted from the node. Serving this model again means `
        + `downloading ${bytes_} and verifying it, which is the cost this button is `
        + `asking you to accept.`,
    }, "danger"));
}

// --- R8-04: routes ---------------------------------------------------------

/** apiRead is api() with the revision the read saw.
 *
 *  09 §2 makes `If-Match` how a read-modify-write refuses to overwrite somebody
 *  else's change. Only the screens that edit a whole object need it, so it is
 *  a second reader rather than a field on every response.
 */
async function apiRead(path) {
  const response = await fetch("/api/v1" + path, { headers: { Accept: "application/json" } });
  if (response.status === 401) {
    window.location.assign("/ui/login");
    throw new Error("unauthenticated");
  }
  const doc = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error((doc.error && doc.error.message) || `${response.status}`);
  return { doc, etag: response.headers.get("ETag") || "" };
}

views.push({
  route: "routes",
  title: "Routes",
  async render() {
    const [routes, deployments] = await Promise.all([apiRead("/routes"), api("/deployments")]);
    const placed = (deployments.deployments || []).map((d) => d.id);

    const rows = (routes.doc.routes || []).map((rt) => {
      const members = (rt.members || []).map((m) => m.deployment_id);
      const picker = el("select", {},
        el("option", { value: "" }, "add a deployment…"),
        placed.filter((id) => !members.includes(id)).map((id) => el("option", { value: id }, id)));
      picker.addEventListener("change", () => {
        if (!picker.value) return;
        // The whole route is replaced, which is what PUT /routes/{name} is:
        // a full replacement, not a merge. Read here, edited here, and sent
        // with the revision it was read at, so two administrators editing the
        // same route collide instead of overwriting each other.
        act({
          title: `Add ${picker.value} to ${rt.name}`,
          method: "PUT", path: "/routes/" + encodeURIComponent(rt.name),
          ifMatch: routes.etag, verb: "Add",
          body: { ...rt, members: [...(rt.members || []), { deployment_id: picker.value, weight: 1 }] },
        });
      });

      return el("tr", {},
        el("td", {}, rt.name),
        el("td", { class: "dim" }, rt.strategy || "—"),
        el("td", {}, members.length
          ? members.map((id) => el("div", { class: "row" }, id,
              button("Remove", {
                title: `Remove ${id} from ${rt.name}`,
                method: "PUT", path: "/routes/" + encodeURIComponent(rt.name),
                ifMatch: routes.etag, verb: "Remove",
                cost: members.length === 1
                  ? "This is the route's last member. A route with nothing ready answers 503, "
                    + "so removing it takes this model off the air."
                  : null,
                body: { ...rt, members: (rt.members || []).filter((m) => m.deployment_id !== id) },
              }, "danger")))
          : el("span", { class: "dim" }, "no member — this route answers 503")),
        el("td", {}, picker));
    });

    show(
      el("h2", {}, "Routes"),
      el("p", { class: "note" },
        "A route carries only members that are ready (06 §2). A route with none answers 503 "
        + "rather than an error from a model server nobody can read."),
      table(["Route", "Strategy", "Members", ""], rows,
        "No route is defined. `nodary model register` creates one."));
  },
});

// --- R8-04: people, their credentials, and what they may spend ------------

/** field builds a labelled input and hands back both, so a form can read it. */
function field(id, label, attrs) {
  const input = el("input", { id, ...(attrs || {}) });
  return { node: el("div", {}, el("label", { for: id }, label), input), input };
}

views.push({
  route: "people",
  title: "People",
  async render() {
    const [users, tokens] = await Promise.all([api("/users"), api("/tokens")]);

    const userRows = (users.users || []).map((u) => el("tr", {},
      el("td", {}, u.name),
      el("td", { class: "dim" }, u.email || "—"),
      el("td", {}, pill(u.role, u.role === "admin" ? "warn" : "")),
      el("td", {}, u.state === "active" ? pill("active", "ok") : pill(u.state, "bad")),
      el("td", {}, u.totp_enrolled ? pill("TOTP", "ok") : el("span", { class: "dim" }, "—")),
      el("td", {}, actions(
        u.state === "active"
          ? button("Suspend", {
              title: `Suspend ${u.name}`, method: "PATCH",
              path: "/users/" + encodeURIComponent(u.name), body: { state: "suspended" },
              verb: "Suspend",
              cost: "Every token this person holds stops working immediately, including any "
                + "unattended one a script is using.",
            })
          : null,
        button("Delete", {
          title: `Delete ${u.name}`, method: "DELETE",
          path: "/users/" + encodeURIComponent(u.name), verb: "Delete",
          cost: "The account goes. The audit chain keeps every act they took — 07 §3 makes "
            + "the record append-only, so deleting a person does not delete what they did.",
        }, "danger")))));

    const tokenRows = (tokens.tokens || []).map((t) => el("tr", {},
      el("td", {}, el("code", {}, t.prefix || t.id)),
      el("td", {}, t.name || el("span", { class: "dim" }, "—")),
      el("td", { class: "dim" }, t.kind),
      el("td", {}, t.state === "active" ? pill("active", "ok") : pill(t.state, "bad")),
      el("td", {}, t.unattended ? pill("unattended", "warn") : el("span", { class: "dim" }, "—")),
      el("td", { class: "dim" }, t.expires_at ? since(t.expires_at) : "never"),
      el("td", {}, t.state === "active"
        ? button("Revoke", {
            title: `Revoke ${t.prefix || t.id}`, method: "DELETE",
            path: "/tokens/" + encodeURIComponent(t.id), verb: "Revoke",
            cost: "Whatever is using this credential stops working the moment this is applied.",
          }, "danger")
        : el("span", { class: "dim" }, "—"))));

    const name = field("u-name", "Username", { autocomplete: "off" });
    const email = field("u-email", "Email", { type: "email", autocomplete: "off" });
    const role = el("select", { id: "u-role" },
      ["viewer", "user", "operator", "admin"].map((r) => el("option", { value: r }, r)));
    const add = el("button", { class: "primary" }, "Add person");
    add.addEventListener("click", () => act({
      title: "Add " + (name.input.value || "a person"),
      path: "/users", verb: "Add",
      body: { name: name.input.value.trim(), email: email.input.value.trim(), role: role.value },
      cost: role.value === "admin"
        ? "An admin can change configuration, register backends, approve nodes and manage "
          + "every other account. 07 §1 gives that role everything."
        : null,
    }));

    show(
      el("h2", {}, "People"),
      table(["Name", "Email", "Role", "State", "Second factor", ""], userRows, "Nobody yet."),
      el("div", { class: "card-inline" },
        name.node, email.node,
        el("label", { for: "u-role" }, "Role"), role,
        el("div", { class: "row" }, add)),

      el("h2", {}, "Credentials"),
      el("p", { class: "note" },
        "A token is shown once, when it is created. nodary keeps a hash and a prefix — there "
        + "is nothing here to read it back from."),
      table(["Prefix", "Name", "Kind", "State", "Unattended", "Expires", ""], tokenRows,
        "No credential has been issued."));
  },
});

// --- R8-04: limits ---------------------------------------------------------

views.push({
  route: "limits",
  title: "Limits",
  async render() {
    const limits = await apiRead("/limits");
    const rows = (limits.doc.limits || []).map((l) => el("tr", {},
      el("td", { class: "dim" }, l.subject_kind),
      el("td", {}, l.subject_id || el("span", { class: "dim" }, "everyone")),
      el("td", { class: "num" }, l.rpm || "—"),
      el("td", { class: "num" }, l.tpm || "—"),
      el("td", { class: "num" }, l.daily_tokens || "—"),
      el("td", { class: "num" }, l.max_concurrent || "—")));

    const kind = el("select", { id: "l-kind" },
      ["user", "model", "route", "global"].map((k) => el("option", { value: k }, k)));
    const id = field("l-id", "Subject (blank for all)", { autocomplete: "off" });
    const rpm = field("l-rpm", "Requests per minute", { inputmode: "numeric" });
    const tpm = field("l-tpm", "Tokens per minute", { inputmode: "numeric" });
    const daily = field("l-daily", "Tokens per day", { inputmode: "numeric" });
    const conc = field("l-conc", "Concurrent requests", { inputmode: "numeric" });

    const apply = el("button", { class: "primary" }, "Set limit");
    apply.addEventListener("click", () => act({
      title: `Set the ${kind.value} limit`,
      method: "PUT",
      path: `/limits/${encodeURIComponent(kind.value)}/${encodeURIComponent(id.input.value.trim() || "-")}`,
      ifMatch: limits.etag, verb: "Set",
      body: {
        subject_kind: kind.value, subject_id: id.input.value.trim(),
        rpm: Number(rpm.input.value) || 0, tpm: Number(tpm.input.value) || 0,
        daily_tokens: Number(daily.input.value) || 0,
        max_concurrent: Number(conc.input.value) || 0,
      },
    }));

    show(
      el("h2", {}, "Limits"),
      el("p", { class: "note" },
        "06 §4: a request over a limit is refused with 429 and a Retry-After, and is not "
        + "metered as served. Zero means no limit of that kind."),
      table(["Kind", "Subject", "RPM", "TPM", "Daily tokens", "Concurrent"], rows,
        "No limit is set, so nothing is throttled."),
      el("div", { class: "card-inline" },
        el("label", { for: "l-kind" }, "Applies to"), kind,
        id.node, rpm.node, tpm.node, daily.node, conc.node,
        el("div", { class: "row" }, apply)));
  },
});

// --- R8-04: the policy profile, and the configuration's history -----------

views.push({
  route: "policy",
  title: "Policy",
  async render() {
    const [policy, revisions] = await Promise.all([api("/policy"), api("/revisions")]);

    const settings = Object.entries(policy)
      .filter(([k]) => k !== "name")
      .map(([k, v]) => el("tr", {},
        el("td", {}, el("code", {}, k)),
        el("td", {}, typeof v === "boolean"
          ? pill(v ? "on" : "off", v ? "ok" : "")
          : String(v))));

    const rows = (revisions.revisions || []).map((rev) => el("tr", {},
      el("td", { class: "num dim" }, rev.seq),
      el("td", { class: "dim" }, since(rev.applied_at || rev.ts)),
      el("td", {}, rev.applied_by || el("span", { class: "dim" }, "—")),
      el("td", {}, rev.justification || el("span", { class: "dim" }, "—")),
      el("td", {}, button("Roll back to this", {
        title: `Roll the configuration back to revision ${rev.seq}`,
        path: `/revisions/${rev.seq}/rollback`, verb: "Roll back",
        cost: "Every object the fleet holds moves to what this revision recorded. Nodes "
          + "converge on it on their next poll, which can stop what is serving now.",
      }, "danger"))));

    show(
      el("h2", {}, "Policy"),
      el("p", {}, "Profile in force: ",
        pill(policy.name, policy.name === "default" ? "" : "warn")),
      el("p", { class: "note" },
        "07 §4: the profile decides what an act costs — whether a justification is "
        + "required and how long it must be, whether a code is re-entered, and what may be "
        + "registered at all."),
      table(["Setting", "Value"], settings, "The profile carries no settings."),
      actions(...["default", "regulated"]
        .filter((p) => p !== policy.name)
        .map((p) => button(`Move to ${p}`, {
          title: `Apply the ${p} profile`, path: "/policy/apply", body: { profile: p },
          verb: "Apply",
          cost: p === "default"
            ? "Loosening. Every act that needed a justification, a code or a pinned recipe "
              + "stops needing one, and the chain will record that this is when it changed."
            : "Tightening. Acts that were free start requiring a justification and a code, "
              + "and a recipe that is not pinned can no longer be built.",
        }, p === "default" ? "danger" : "primary"))),

      el("h2", {}, "Configuration history"),
      el("p", { class: "note" },
        "Each revision carries a complete snapshot and its hash. `nodary config verify` walks "
        + "the chain; this is what it walks."),
      table(["Seq", "Applied", "By", "Why", ""], rows, "No revision has been applied."));
  },
});


/** restartButton is 03 §7's rolling restart, from the one screen that knows
 *  which node a deployment is on — `?node=` is required for a restart, which is
 *  inherently one machine's act.
 *
 *  `allowDowntime` carries the path to retry with rather than a flag, so the
 *  decision to accept the gap is a different request and not a boolean this
 *  page could set on its own.
 */
function restartButton(node, d) {
  if (d.disabled) return el("span", { class: "dim" }, "disabled");
  const at = "/models/" + encodeURIComponent(d.model_id) + "/restart?node="
    + encodeURIComponent(node.name);
  return button("Restart", {
    title: `Restart ${d.model_id} on ${node.name}`,
    path: at, verb: "Restart",
    allowDowntime: at + "&allow_downtime=true",
  });
}
