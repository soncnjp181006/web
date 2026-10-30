import React from "react";

/* OAuth misconfiguration demos (#62). */
export default function OAuthDemo() {
  const cb = encodeURIComponent(`${window.location.origin}/api/oauth/client/callback`);
  return (
    <div>
      <h1>OAuth lab (#62)</h1>
      <div className="card">
        <h2>Authorization code flow (redirect_uri không kiểm tra)</h2>
        <p className="hint">
          <code>redirect_uri</code> chấp nhận BẤT KỲ giá trị nào → code gửi tới attacker domain (code interception).
          <br />
          <code>state</code> không được validate phía client → login CSRF.
        </p>
        <a
          className="row"
          href={`/api/oauth/authorize?client_id=vuln-client&redirect_uri=${cb}&response_type=code&state=unused`}
        >
          <button className="primary">Start code flow (về callback của app này)</button>
        </a>
        <a
          className="row"
          href={`/api/oauth/authorize?client_id=vuln-client&redirect_uri=${encodeURIComponent(
            "https://example.com/attacker-cb"
          )}&response_type=code`}
        >
          <button className="danger">Gửi code tới https://example.com (redirect_uri không validate)</button>
        </a>
      </div>
      <div className="card">
        <h2>Implicit flow (token trong URL fragment)</h2>
        <a
          href={`/api/oauth/authorize?client_id=vuln-client&redirect_uri=${cb}&response_type=token`}
        >
          <button>Start implicit flow</button>
        </a>
      </div>
    </div>
  );
}
