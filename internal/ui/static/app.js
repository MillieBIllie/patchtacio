// Patchtacio's only script: product search and "working" feedback on slow
// buttons. Every page works without it.
(function () {
  "use strict";

  // Search: hide product rows that do not contain every typed word.
  document.querySelectorAll("input[data-filter]").forEach(function (box) {
    var rows = document.querySelectorAll(box.getAttribute("data-filter"));
    box.addEventListener("input", function () {
      var words = box.value.toLowerCase().split(/\s+/).filter(Boolean);
      rows.forEach(function (row) {
        var text = row.getAttribute("data-search") || "";
        row.hidden = !words.every(function (w) { return text.indexOf(w) >= 0; });
      });
    });
  });

  // Count of ticked products.
  document.querySelectorAll("[data-ticked]").forEach(function (out) {
    var table = document.querySelector(out.getAttribute("data-ticked"));
    if (!table) { return; }
    var update = function () {
      var n = table.querySelectorAll("input[name=pick]:checked").length;
      out.textContent = n + " ticked";
    };
    table.addEventListener("change", update);
  });

  // Slow actions (downloads, tests): say so, and stop double submits.
  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      var clicked = ev.submitter;
      if (clicked && clicked.name) {
        // A disabled button's value is not sent; keep it.
        var keep = document.createElement("input");
        keep.type = "hidden";
        keep.name = clicked.name;
        keep.value = clicked.value;
        form.appendChild(keep);
      }
      form.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
      if (clicked) { clicked.textContent = "Working, please wait…"; }
      document.body.classList.add("busy");
    });
  });
})();
