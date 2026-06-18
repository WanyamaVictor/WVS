// Console page: module select-all + live SSE scan streaming.
(function () {
  "use strict";

  // --- "all" master checkbox ---
  var allBox = document.getElementById("mod-all");
  var modBoxes = Array.prototype.slice.call(
    document.querySelectorAll('input[name="modules"]')
  );
  if (allBox) {
    allBox.addEventListener("change", function () {
      modBoxes.forEach(function (b) { b.checked = allBox.checked; });
    });
    modBoxes.forEach(function (b) {
      b.addEventListener("change", function () {
        allBox.checked = modBoxes.every(function (x) { return x.checked; });
      });
    });
  }

  var form = document.getElementById("scan-form");
  if (!form) return;

  var btn = document.getElementById("launch-btn");
  var panel = document.getElementById("progress-panel");
  var fill = document.getElementById("prog-fill");
  var label = document.getElementById("prog-label");
  var logEl = document.getElementById("prog-log");
  var target = document.getElementById("prog-target");
  var banner = document.getElementById("error-banner");

  function showError(msg) {
    banner.textContent = msg;
    banner.style.display = "block";
  }
  function appendLog(line) {
    logEl.textContent += line + "\n";
    logEl.scrollTop = logEl.scrollHeight;
  }
  function setProgress(pct) { fill.style.width = Math.max(0, Math.min(100, pct)) + "%"; }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    banner.style.display = "none";

    var data = new FormData(form);
    btn.disabled = true;
    btn.textContent = "Scanning…";

    fetch("/scan/start", { method: "POST", body: data })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (!res.ok) {
          showError(res.j.error || "Could not start scan.");
          btn.disabled = false;
          btn.textContent = "Launch Scan";
          return;
        }
        startStream(res.j.job_id, res.j.target);
      })
      .catch(function () {
        showError("Network error starting scan.");
        btn.disabled = false;
        btn.textContent = "Launch Scan";
      });
  });

  function startStream(jobId, tgt) {
    panel.style.display = "block";
    logEl.textContent = "";
    setProgress(2);
    label.textContent = "starting…";
    if (target) target.textContent = "» " + tgt;

    var es = new EventSource("/scan/stream/" + jobId);
    es.onmessage = function (ev) {
      var d;
      try { d = JSON.parse(ev.data); } catch (_) { return; }

      if (d.type === "phase") {
        var pct = d.total ? Math.round(((d.index - 1) / d.total) * 100) : 0;
        setProgress(Math.max(pct, 3));
        label.textContent = "[" + d.index + "/" + d.total + "] " + d.label;
        appendLog("[*] " + d.label);
      } else if (d.type === "log") {
        appendLog("    " + d.message);
      } else if (d.type === "done") {
        setProgress(98);
        label.textContent = "finalizing…";
      } else if (d.type === "complete") {
        setProgress(100);
        label.textContent = "complete — risk " + d.risk_score + "/100, " +
          d.findings + " finding(s). Opening report…";
        es.close();
        window.location = "/scan/" + d.scan_id;
      } else if (d.type === "error") {
        es.close();
        showError(d.message || "Scan failed.");
        btn.disabled = false;
        btn.textContent = "Launch Scan";
      }
    };
    es.onerror = function () {
      // Stream closed (often right after redirect); only surface if still running.
      if (btn.disabled && fill.style.width !== "100%") {
        showError("Connection to scan stream lost.");
        btn.disabled = false;
        btn.textContent = "Launch Scan";
      }
      es.close();
    };
  }
})();
