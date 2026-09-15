// The console starts a session the way every other client does: it posts to
// /api/v1/auth/login and takes the cookie that endpoint issues. There is no
// second way in, which is what keeps dev/specs/07-identity-audit.md §1's
// "short-lived signed session cookies" one mechanism rather than two.
const form = document.getElementById("login");
const problem = document.getElementById("problem");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  problem.hidden = true;
  const body = {
    username: document.getElementById("username").value,
    password: document.getElementById("password").value,
  };
  // No code field: POST /auth/login takes a username and a password and
  // nothing else. dev/specs/07-identity-audit.md §2 makes TOTP a property of
  // an *act* rather than of a session — R8-03 asks for it at the moment of a
  // mutation, where a live cookie does not satisfy it. A box here would be a
  // control that does nothing, which is the kind that gets written into a
  // System Security Plan by mistake.

  let response;
  try {
    response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (err) {
    return show("The control plane could not be reached.");
  }
  if (response.ok) {
    window.location.assign("/ui/");
    return;
  }
  // The server's own message, which already says "incorrect username or
  // password" without telling a caller which — a page that invented its own
  // wording here would be the second place that decision lives.
  let doc = {};
  try { doc = await response.json(); } catch (err) { /* an empty body is still a refusal */ }
  const retry = response.headers.get("Retry-After");
  let message = (doc.error && doc.error.message) || "Sign in failed.";
  if (retry) message += ` Try again in ${retry}s.`;
  show(message);
});

function show(message) {
  problem.textContent = message;
  problem.hidden = false;
}
