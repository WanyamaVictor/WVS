// Scan-view page: expandable detail rows + severity/text filtering + column sort.
(function () {
  "use strict";

  var table = document.getElementById("findings-table");
  if (!table) return;
  var tbody = table.querySelector("tbody");
  var search = document.getElementById("finding-search");
  var noMatch = document.getElementById("no-match");
  var sevButtons = Array.prototype.slice.call(document.querySelectorAll(".fbtn"));

  // Pair each finding row with its detail row.
  function pairs() {
    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr.finding-row"));
    return rows.map(function (r) { return { main: r, detail: r.nextElementSibling }; });
  }

  // --- expand/collapse ---
  tbody.addEventListener("click", function (e) {
    var row = e.target.closest("tr.finding-row");
    if (!row) return;
    var detail = row.nextElementSibling;
    if (detail && detail.classList.contains("detail-row")) {
      var open = detail.style.display !== "none";
      detail.style.display = open ? "none" : "table-row";
      row.classList.toggle("expanded", !open);
    }
  });

  // --- filtering ---
  var activeSev = "all";
  function applyFilter() {
    var q = (search ? search.value : "").trim().toLowerCase();
    var visible = 0;
    pairs().forEach(function (p) {
      var sevOk = activeSev === "all" || p.main.getAttribute("data-sev") === activeSev;
      var textOk = !q || p.main.getAttribute("data-text").indexOf(q) !== -1;
      var show = sevOk && textOk;
      p.main.style.display = show ? "table-row" : "none";
      if (p.detail) p.detail.style.display = "none";
      if (show) visible++;
    });
    if (noMatch) noMatch.style.display = visible ? "none" : "block";
  }

  sevButtons.forEach(function (b) {
    b.addEventListener("click", function () {
      sevButtons.forEach(function (x) { x.classList.remove("active"); });
      b.classList.add("active");
      activeSev = b.getAttribute("data-sev");
      applyFilter();
    });
  });
  if (search) search.addEventListener("input", applyFilter);

  // --- sorting ---
  var sortState = { key: null, dir: 1 };
  function cellText(row, key) {
    if (key === "sev") return parseInt(row.getAttribute("data-rank"), 10);
    var idx = key === "type" ? 1 : 2; // type col 1, endpoint col 2
    return row.children[idx].textContent.trim().toLowerCase();
  }
  table.querySelectorAll("th[data-sort]").forEach(function (th) {
    th.classList.add("sortable");
    th.addEventListener("click", function () {
      var key = th.getAttribute("data-sort");
      sortState.dir = sortState.key === key ? -sortState.dir : 1;
      sortState.key = key;
      var ps = pairs().sort(function (a, b) {
        var va = cellText(a.main, key), vb = cellText(b.main, key);
        if (va < vb) return -1 * sortState.dir;
        if (va > vb) return 1 * sortState.dir;
        return 0;
      });
      ps.forEach(function (p) {
        tbody.appendChild(p.main);
        if (p.detail) tbody.appendChild(p.detail);
      });
      table.querySelectorAll("th[data-sort]").forEach(function (h) {
        h.classList.remove("asc", "desc");
      });
      th.classList.add(sortState.dir === 1 ? "asc" : "desc");
    });
  });
})();
