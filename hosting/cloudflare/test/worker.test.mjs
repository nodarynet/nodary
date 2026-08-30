// Behavioural tests for the releases Worker, against a mock R2 binding.
//
//   node hosting/cloudflare/test/worker.test.mjs
//
// The mock matters more than it looks. An earlier version only populated
// `range` when the request carried a Range header, and so happily passed a
// Worker that answered *every* GET with a 206 covering the whole file. Real R2
// populates `range` on a full-object get too. The mock below does what R2 does;
// keep it that way, or these tests stop meaning anything.

import worker from "../src/index.js";

const INSTALLER = Buffer.from("#!/bin/sh\n# nodary installer\n");
const BINARY = Buffer.alloc(4096, 7);

const store = new Map([
  ["install.sh", { bytes: INSTALLER, ct: "text/plain; charset=utf-8", cc: "public, max-age=300", etag: '"a"' }],
  ["install.sh.minisig", { bytes: Buffer.from("sig\n"), ct: "text/plain; charset=utf-8", cc: "public, max-age=300", etag: '"b"' }],
  ["releases/1.4.0/nodary-1.4.0-linux-amd64", { bytes: BINARY, ct: "application/octet-stream", cc: "public, max-age=31536000, immutable", etag: '"c"' }],
]);

const obj = (e, extra = {}) => ({
  size: e.bytes.length,
  httpEtag: e.etag,
  writeHttpMetadata(h) { h.set("content-type", e.ct); h.set("cache-control", e.cc); },
  ...extra,
});

const env = {
  RELEASES: {
    async head(k) { const e = store.get(k); return e ? obj(e) : null; },
    async get(k, opts = {}) {
      const e = store.get(k);
      if (!e) return null;
      if (opts.onlyIf?.get("if-none-match") === e.etag) return obj(e, { body: null });
      const r = opts.range?.get("range");
      if (r) {
        const [, a, b] = r.match(/bytes=(\d+)-(\d*)/);
        const off = Number(a), end = b ? Number(b) : e.bytes.length - 1;
        return obj(e, { body: e.bytes.subarray(off, end + 1), range: { offset: off, end } });
      }
      // As R2 does: `range` is present even when none was asked for.
      return obj(e, { body: e.bytes, range: { offset: 0, end: e.bytes.length - 1 } });
    },
  },
};

let failed = 0;
async function check(name, path, init, want) {
  const res = await worker.fetch(new Request("https://nodary.net" + path, init), env);
  const bad = Object.entries(want).filter(([k, v]) =>
    k === "status" ? res.status !== v : String(res.headers.get(k)) !== String(v));
  if (bad.length) {
    failed++;
    console.log(`  FAIL ${name}`);
    for (const [k] of bad) console.log(`         ${k}: got ${k === "status" ? res.status : res.headers.get(k)}, want ${want[k]}`);
  } else {
    console.log(`  ok   ${name}`);
  }
}

// The regression this file exists for.
await check("plain GET is 200 and carries no content-range", "/install.sh", {},
  { status: 200, "content-range": null });

await check("install.sh keeps its short TTL", "/install.sh", {},
  { status: 200, "cache-control": "public, max-age=300", "content-type": "text/plain; charset=utf-8" });
await check("a release asset is immutable", "/releases/1.4.0/nodary-1.4.0-linux-amd64", {},
  { status: 200, "cache-control": "public, max-age=31536000, immutable" });
await check("HEAD carries content-length", "/install.sh", { method: "HEAD" },
  { status: 200, "content-length": INSTALLER.length });
await check("a range request is 206 with content-range", "/releases/1.4.0/nodary-1.4.0-linux-amd64",
  { headers: { range: "bytes=100-199" } }, { status: 206, "content-range": "bytes 100-199/4096" });
await check("a matching conditional is 304", "/install.sh",
  { headers: { "if-none-match": '"a"' } }, { status: 304 });
await check("ranges are advertised", "/install.sh", {}, { status: 200, "accept-ranges": "bytes" });
await check("nosniff is set", "/install.sh", {}, { status: 200, "x-content-type-options": "nosniff" });
await check("POST is refused", "/install.sh", { method: "POST" }, { status: 405, allow: "GET, HEAD" });

// Paths that reach the Worker but are not published. Anything outside the three
// routes never arrives here at all — Cloudflare does not match it.
await check("an absent object is 404", "/releases/9.9.9/nope", {}, { status: 404 });
await check("a nested path under releases/ is 404", "/releases/1.4.0/a/b", {}, { status: 404 });
await check("traversal is 404", "/releases/../../secret", {}, { status: 404 });
await check("encoded traversal is 404", "/releases/1.4.0/%2e%2e%2f%2e%2e%2fsecret", {}, { status: 404 });
await check("a directory probe is 404", "/releases/", {}, { status: 404 });
await check("malformed percent-encoding is 404", "/install.sh%ZZ", {}, { status: 404 });

console.log(failed ? `\n${failed} failed` : "\nall passed");
process.exit(failed ? 1 : 0);
