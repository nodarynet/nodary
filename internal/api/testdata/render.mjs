// Run every console view against a real control plane, in a DOM small enough
// to read.
//
// internal/api/ui_test.go drives this: it stands up the real handlers, signs
// in, and points ORIGIN at them. What it answers is the one question the Go
// tests could not — whether the code in each view *runs*. Everything else
// about the console is checked by reading it: which endpoints it names, which
// screens it declares, which tokens its stylesheet uses. None of that executes
// a line of it, and the console's own history is of things that read correctly
// and rendered nothing.
//
// This is not a browser and does not pretend to be one. It has no layout, no
// CSS and no events, so it cannot see a screen that renders into an invisible
// corner. It sees a view that throws, and a view that produces no text at all.
import fs from "node:fs";
import vm from "node:vm";

const ORIGIN = process.env.ORIGIN;
const COOKIE = process.env.COOKIE || "";
const NODE_NAME = process.env.NODE_NAME || "";
const DEPLOYMENT = process.env.DEPLOYMENT || "";
if (!ORIGIN) {
  console.error("ORIGIN is not set; this is driven by ui_test.go, not run by hand");
  process.exit(2);
}

/** El is as much of an Element as app.js touches, and no more. */
class El {
  constructor(tag) { this.tag = tag; this.attrs = {}; this.kids = []; this.style = {}; this._text = ""; }
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k]; }
  append(...c) { this.kids.push(...c); }
  replaceChildren(...c) { this.kids = c; }
  addEventListener() {}
  showModal() {}
  close() {}
  querySelector() { return null; }
  set textContent(v) { this._text = String(v); this.kids = []; }
  get textContent() {
    if (this._text) return this._text;
    return this.kids.map((k) => (k instanceof El ? k.textContent : String(k))).join("");
  }
  set className(v) { this.attrs.class = v; }
  get className() { return this.attrs.class || ""; }
  set value(v) { this._value = v; }
  get value() { return this._value || ""; }
}

const byId = {};
const context = {
  Node: El,
  console,
  Date, Math, JSON, Number, String, Object, Array, Boolean, Promise, Error, RegExp, Map, Set,
  isNaN, parseInt, parseFloat, encodeURIComponent, decodeURIComponent, setTimeout, clearTimeout,
  document: {
    getElementById: (id) => (byId[id] ||= new El("div")),
    createElement: (tag) => new El(tag),
    createTextNode: (t) => String(t),
    addEventListener() {},
  },
  window: {
    // A redirect to the login page means the session did not reach the API,
    // which is a failure of this harness rather than of the view — so it is
    // loud rather than silent.
    location: { hash: "", assign(to) { throw new Error("the console navigated away to " + to); } },
    addEventListener() {},
    sessionStorage: { getItem: () => null, setItem() {} },
  },
  // A page sends a relative URL; node's fetch wants an origin, and the session
  // rides on a header because there is no cookie jar here.
  fetch: (path, init = {}) =>
    fetch(ORIGIN + path, { ...init, headers: { ...(init.headers || {}), Cookie: COOKIE } }),
};
context.globalThis = context;

const source = fs.readFileSync(process.argv[2], "utf8");
vm.runInNewContext(source + "\n;globalThis.__views = views;", context);

const view = (byId.view ||= new El("main"));
const argument = { node: NODE_NAME, logs: DEPLOYMENT };
let failed = 0;

for (const screen of context.__views) {
  try {
    await screen.render(argument[screen.route] || "");
    const text = view.kids
      .map((k) => (k instanceof El ? k.textContent : String(k)))
      .join(" ").replace(/\s+/g, " ").trim();
    if (!text) {
      console.log(`EMPTY  ${screen.route}: rendered without throwing and put nothing on the page`);
      failed++;
      continue;
    }
    // A screen that prints one of these is a screen that let a JavaScript
    // value reach the page as a word. `replaceChildren` stringifies anything
    // that is not a Node, so `cond ? el(…) : null` renders "null" unless it is
    // filtered — which is exactly the bug this harness was written by finding.
    for (const leak of ["null", "undefined", "[object Object]", "NaN"]) {
      if (text.split(/[\s,.;:()]+/).includes(leak)) {
        console.log(`LEAKED ${screen.route}: the word "${leak}" reached the page`);
        failed++;
        break;
      }
    }
    console.log(`ok     ${screen.route}`);
    // The text itself, so a caller can assert that a fact reached the page
    // rather than only that the page was not blank. Bounded, because a screen
    // with a hundred rows is not a useful thing to print.
    console.log(`text   ${screen.route}: ${text.slice(0, 600)}`);
  } catch (err) {
    console.log(`THREW  ${screen.route}: ${(err && err.stack) || err}`);
    failed++;
  }
}

console.log(failed ? `${failed} view(s) did not render` : `all ${context.__views.length} views rendered`);
process.exit(failed ? 1 : 0);
