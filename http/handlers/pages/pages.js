// Reads the single-use token from the URL fragment (never sent to servers)
// and posts it to the API.
(function () {
  "use strict";
  var token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
  // Where to go after verifying (checked again by the server).
  var returnTo = new URLSearchParams(location.search).get("return_to") || "";
  // Drop the token (and return_to) from the address bar and history.
  if (location.hash || location.search) history.replaceState(null, "", location.pathname);
  var status = document.getElementById("status");
  function say(msg, isError) {
    status.textContent = msg;
    status.className = isError ? "error" : "";
  }
  function post(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Requested-With": "fetch" },
      body: JSON.stringify(body),
      credentials: "same-origin"
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        return { ok: res.ok, data: data };
      });
    });
  }
  if (!token) {
    say("This link is missing its token. Open the link from your email again.", true);
    var f = document.getElementById("reset");
    if (f) f.hidden = true;
    return;
  }
  var page = document.body.getAttribute("data-page");
  if (page === "verify") {
    post("/v1/email/verify", { token: token, return_to: returnTo }).then(function (r) {
      if (!r.ok) {
        say(r.data.error === "invalid_token"
          ? "This link has expired or was already used. Sign in to the app to get a new one."
          : (r.data.message || "Verification failed."), true);
        return;
      }
      var to = typeof r.data.redirect_to === "string" ? r.data.redirect_to : "";
      // The server only returns allowed targets; still never follow
      // anything but web or app links.
      if (!/^(https?|boson):\/\//i.test(to)) to = "";
      var actions = document.getElementById("actions");
      var btn = document.getElementById("continue");
      if (to) {
        say("Your email address is verified. Taking you back to the app…");
        btn.href = to;
        btn.textContent = "Continue";
        actions.hidden = false;
        setTimeout(function () { location.assign(to); }, 2500);
      } else {
        // No web client configured: offer the desktop app (boson:// is
        // registered by the Boson desktop app), else just close the page.
        say("Your email address is verified. Go back to the app and sign in, or close this page.");
        btn.href = "boson://open";
        btn.textContent = "Open the Boson app";
        btn.className = "button secondary";
        actions.hidden = false;
      }
    }, function () { say("Network error. Try again.", true); });
  } else if (page === "reset") {
    var form = document.getElementById("reset");
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var pw = form.pw.value;
      if (pw !== form.pw2.value) { say("The passwords don't match.", true); return; }
      var btn = form.querySelector("button");
      btn.disabled = true;
      post("/v1/password/reset", { token: token, new_password: pw }).then(function (r) {
        if (r.ok) {
          form.hidden = true;
          say("Password changed. You've been signed out everywhere; sign in with the new password.");
        } else {
          btn.disabled = false;
          say(r.data.message || "Reset failed.", true);
        }
      }, function () { btn.disabled = false; say("Network error. Try again.", true); });
    });
  }
})();
