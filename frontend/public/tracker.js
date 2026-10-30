/**
 * [VULN #51] Third-party tracking demo: persistent cross-session id in
 * localStorage + pageview beacons to the collector + 1x1 pixel.
 */
(function () {
  try {
    var uid = localStorage.getItem("vulnshop_track_uid");
    if (!uid) {
      uid = "t-" + Math.random().toString(36).slice(2) + Date.now().toString(36);
      localStorage.setItem("vulnshop_track_uid", uid);
    }
    window.__vulnTracker = { uid: uid, pageviews: 0 };

    function beacon() {
      window.__vulnTracker.pageviews++;
      fetch("/api/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ src: "tracker", kind: "pageview", uid: uid, page: location.pathname, ref: document.referrer }),
      }).catch(function () {});
      // classic 1x1 pixel beacon
      var px = new Image();
      px.src = "/api/net/echo-headers?track=" + encodeURIComponent(uid) + "&cb=" + Date.now();
    }

    beacon();
    // also record SPA navigations
    var push = history.pushState;
    history.pushState = function () {
      beacon();
      return push.apply(this, arguments);
    };
  } catch (e) {}
})();
