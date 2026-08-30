// Serves the nodary release artifacts from R2 on the nodary.net apex.
//
// install.sh hardcodes https://nodary.net as its origin (01-install.md §2), so
// the artifacts have to live on the apex rather than a subdomain. This Worker
// is bound only to the three paths that serve them, leaving the rest of the
// apex free for whatever else the zone hosts.
//
// It is deliberately a dumb file server. Everything that makes an artifact
// trustworthy — the signature, the digest — is verified by install.sh against
// keys published somewhere other than here, so this Worker is not in a position
// to vouch for anything and does not try to.

// Only the published shape resolves. Path traversal, directory probes and
// anything else get one answer, before R2 is touched.
const PUBLISHED = /^(?:install\.sh(?:\.minisig)?|releases\/[A-Za-z0-9][A-Za-z0-9._+-]*\/[A-Za-z0-9][A-Za-z0-9._-]*)$/;

const notFound = () =>
  new Response("not found\n", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });

function baseHeaders(object) {
  const headers = new Headers();
  // content-type and cache-control are set when the release workflow uploads
  // the object, so the caching policy lives with the artifact rather than being
  // reconstructed from the path here.
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("accept-ranges", "bytes");
  headers.set("x-content-type-options", "nosniff");
  return headers;
}

export default {
  async fetch(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed\n", {
        status: 405,
        headers: { allow: "GET, HEAD", "content-type": "text/plain; charset=utf-8" },
      });
    }

    let key;
    try {
      key = decodeURIComponent(new URL(request.url).pathname).replace(/^\/+/, "");
    } catch {
      return notFound(); // malformed percent-encoding
    }
    if (!PUBLISHED.test(key)) return notFound();

    if (request.method === "HEAD") {
      const object = await env.RELEASES.head(key);
      if (object === null) return notFound();
      const headers = baseHeaders(object);
      headers.set("content-length", String(object.size));
      return new Response(null, { status: 200, headers });
    }

    // Range matters here: the binaries are 20–40 MB and a resumed download
    // beats restarting one.
    const object = await env.RELEASES.get(key, {
      range: request.headers,
      onlyIf: request.headers,
    });
    if (object === null) return notFound();

    const headers = baseHeaders(object);

    // No body means the conditional request matched what the client already has.
    if (!object.body) return new Response(null, { status: 304, headers });

    if (object.range) {
      const offset = object.range.offset ?? 0;
      const end = object.range.end ?? object.size - 1;
      headers.set("content-range", `bytes ${offset}-${end}/${object.size}`);
      return new Response(object.body, { status: 206, headers });
    }

    return new Response(object.body, { status: 200, headers });
  },
};
