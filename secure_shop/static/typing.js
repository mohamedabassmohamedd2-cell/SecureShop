// Lab 4 helper: capture the password keystroke rhythm on the login form and
// attach it as hidden fields (typing_speed in keys/sec, gap_mean in seconds)
// so the server can run the z-score anomaly detector. Purely additive: if the
// field or form is missing, nothing happens.
(function () {
  "use strict";
  var pw = document.querySelector('form input[name="password"]');
  if (!pw || !pw.form) { return; }
  var form = pw.form;
  var stamps = [];

  pw.addEventListener("keydown", function () {
    stamps.push(performance.now());
  });

  form.addEventListener("submit", function () {
    if (stamps.length < 2) { return; }
    var gaps = [];
    for (var i = 1; i < stamps.length; i++) {
      gaps.push((stamps[i] - stamps[i - 1]) / 1000.0);
    }
    var total = (stamps[stamps.length - 1] - stamps[0]) / 1000.0;
    if (total <= 0) { return; }
    var speed = gaps.length / total; // keys per second
    var mean = 0;
    for (var j = 0; j < gaps.length; j++) { mean += gaps[j]; }
    mean = mean / gaps.length;

    function hidden(name, value) {
      var el = document.createElement("input");
      el.type = "hidden";
      el.name = name;
      el.value = value.toFixed(3);
      form.appendChild(el);
    }
    hidden("typing_speed", speed);
    hidden("gap_mean", mean);
  });
})();
