// Reads the single-use token from the URL fragment (never sent to servers)
// and posts it to the API.
(function () {
  "use strict";
  var token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
  // Drop the token from the address bar and history.
  if (location.hash) history.replaceState(null, "", location.pathname);
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
    post("/v1/email/verify", { token: token }).then(function (r) {
      say(r.ok ? "Your email address is verified. You can close this page and sign in."
               : (r.data.message || "Verification failed."), !r.ok);
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
