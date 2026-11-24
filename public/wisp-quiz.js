// WISP readiness quiz, shared by /wisp and /wisp/quiz. Live score with the
// same math as the emailed report; the quiz Lambda scores the answers again
// (src/quiz/quizzes/wisp/scoring.js). Option 1 is worth 2 points, option 2 is
// 1, option 3 is 0. Questions 11 and 12 start empty and must be answered
// before the report can be sent.
(function () {
  var form = document.getElementById("quiz-form");
  if (!form) return;
  var POINTS = [2, 1, 0], N_Q = 10;
  var $ = function (id) { return document.getElementById(id); };
  var money = function (n) { return "$" + Math.round(n).toLocaleString("en-US"); };
  var BANDS = { none: "Answer to begin", good: "In good shape", mid: "Partly covered", low: "Starting point" };
  var MSGS = {
    good: "You have most of it in place. A yearly review keeps it that way.",
    mid: "You have the pieces. They need to be written down and checked. Start with Secure in a Day.",
    low: "Plenty of offices start here. One working session gets you a real plan. Start with Secure in a Day."
  };

  function picks() {
    var out = [];
    for (var i = 0; i < N_Q; i++) {
      var c = form.querySelector('input[name="q' + i + '"]:checked');
      out.push(c ? Number(c.value) : null);
    }
    return out;
  }
  function num(id) { return Math.max(0, +$(id).value || 0); }
  function filled(id) { return $(id).value.trim() !== ""; }

  function render() {
    var a = picks(), pts = a.map(function (x) { return x === null ? null : POINTS[x]; });
    var R = num("inR"), N = num("inN"), F = num("inF"), D = Math.max(1, Math.round(+$("inD").value || 1));
    var score = 0, answered = 0;
    pts.forEach(function (p) { if (p !== null) { answered++; score += p; } });
    var backup = pts[5], days = backup === 2 ? 3 : (backup === 0 ? 21 : 10);
    var A = R * 181, B = Math.round((N * F / 75) * days), C = Math.min(R * 250, 10000);
    var missing = [2, 3, 4, 8].filter(function (ix) { return pts[ix] === 0; }).length;
    var band = answered < N_Q ? "none" : (score >= 16 ? "good" : (score >= 9 ? "mid" : "low"));
    $("score").textContent = score;
    $("bar").style.width = (score / 20 * 100) + "%";
    $("band").textContent = BANDS[band]; $("band").className = "pill " + band;
    $("msg").textContent = answered < N_Q
      ? "You have answered " + (answered + (filled("inD") ? 1 : 0) + (filled("inN") ? 1 : 0)) + " of 12 questions."
      : MSGS[band];
    $("aNote").textContent = R.toLocaleString("en-US") + " records x $181";
    var why = backup === 2 ? "backup tested" : (backup === 0 ? "no backup" : (backup === 1 ? "backup not tested" : "backup question not answered yet"));
    $("bNote").textContent = filled("inN") ? days + " days down assumed (" + why + ")" : "Answer question 12 to include this line";
    $("vA").textContent = money(A); $("vB").textContent = money(B); $("vC").textContent = money(C); $("vT").textContent = money(A + B + C);
    $("ceil").innerHTML = missing === 0
      ? "<b>Legal maximum, not a forecast.</b> The FTC ceiling is $53,088 per violation. Your answers so far show no missing written items from questions 3, 4, 5 and 9."
      : "<b>Legal maximum, not a forecast: " + money(missing * 53088) + ".</b> The FTC ceiling is $53,088 per violation. Your answers show " + missing + " missing written item" + (missing > 1 ? "s" : "") + " from questions 3, 4, 5 and 9. Small offices rarely see the full amount.";
    return a;
  }

  form.addEventListener("change", function (e) {
    var fs = e.target.closest("fieldset"); if (fs) fs.classList.remove("missing");
    render();
  });
  ["inR", "inN", "inF", "inD"].forEach(function (id) {
    $(id).addEventListener("input", function () {
      var fs = $(id).closest("fieldset"); if (fs) fs.classList.remove("missing");
      render();
    });
  });

  var status = $("status"), btn = $("sendBtn");
  function say(text, kind) { status.textContent = text; status.className = "status" + (kind ? " " + kind : ""); }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var a = render();
    var gaps = [];
    a.forEach(function (x, i) { if (x === null) gaps.push(i + 1); });
    if (!filled("inD")) gaps.push(11);
    if (!filled("inN")) gaps.push(12);
    if (gaps.length) {
      gaps.forEach(function (n) { $("fs-q" + n).classList.add("missing"); });
      var first = gaps[0];
      say("Question " + first + " needs an answer before we can send your report.", "err");
      if (first <= N_Q) form.querySelector('input[name="q' + (first - 1) + '"]').focus();
      else $(first === 11 ? "inD" : "inN").focus();
      return;
    }
    var email = $("email").value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { say("Enter your email address so we can send your report.", "err"); $("email").focus(); return; }
    btn.disabled = true; say("Sending your report...");
    fetch("/api/quiz/wisp/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ answers: a, devices: +$("inD").value, returns: +$("inN").value, records: +$("inR").value, fee: +$("inF").value, email: email, newsletter_opt_in: $("newsletter").checked === true })
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (j) { return { ok: res.ok, j: j }; });
    }).then(function (r) {
      if (r.ok && r.j.report_emailed) say("Sent. Your report is on its way to " + email + ".", "ok");
      else if (r.ok) say("We scored your answers but could not send the email. Please try again in a moment.", "err");
      else {
        say(r.j.error || "Something went wrong. Please try again in a moment.", "err");
        if (r.j.field === "email") $("email").focus();
      }
    }).catch(function () {
      say("We could not reach the server. Check your connection and try again.", "err");
    }).then(function () { btn.disabled = false; });
  });

  render();
})();
