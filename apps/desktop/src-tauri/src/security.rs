// SPDX-License-Identifier: Apache-2.0
//! Pure validation and crypto helpers for the desktop shell. Everything that
//! decides what the webview may reach or what the loopback listener accepts
//! lives here, so it can be unit tested without Tauri or a network.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

/// Errors surfaced to the webview. Messages are generic on purpose.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Invalid {
    #[error("the server URL must be https (http is allowed only for localhost)")]
    ServerUrl,
    #[error("this request is not allowed")]
    Request,
    #[error("the sign-in response was not valid")]
    Callback,
}

/// Validates and normalizes a Kiln server URL to its origin. Only https is
/// accepted, except http on a loopback host for local development.
pub fn normalize_server_url(raw: &str) -> Result<Url, Invalid> {
    let url = Url::parse(raw.trim()).map_err(|_| Invalid::ServerUrl)?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(Invalid::ServerUrl);
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(Invalid::ServerUrl);
    }
    let host = url.host_str().ok_or(Invalid::ServerUrl)?;
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(Invalid::ServerUrl),
    }
    let origin = url.origin().ascii_serialization();
    Url::parse(&origin).map_err(|_| Invalid::ServerUrl)
}

const ALLOWED_METHODS: [&str; 4] = ["GET", "POST", "PUT", "DELETE"];

fn allowed_api_path(p: &str) -> bool {
    p.starts_with("/api/v1/") && !p.starts_with("/api/v1/auth/")
}

/// Validates a webview API request and returns the method and the URL to call.
/// The webview may only reach Kiln's API under /api/v1/ on the configured
/// server; the auth endpoints are driven by Rust alone, so they are excluded.
///
/// The rules are checked on the raw path *and* on the URL after joining, and
/// the two paths must be identical: URL parsing treats encoded dot-segments
/// such as `%2e%2e` as `..`, so a check on the raw string alone can be
/// bypassed (security review, desktop M1).
pub fn api_target(server: &Url, method: &str, path: &str) -> Result<(reqwest::Method, Url), Invalid> {
    if !ALLOWED_METHODS.contains(&method) {
        return Err(Invalid::Request);
    }
    let raw_path = path.split_once('?').map_or(path, |(p, _)| p);
    let lower = raw_path.to_ascii_lowercase();
    let valid_raw = allowed_api_path(path)
        && path.len() <= 2048
        && !path.contains("..")
        && !path.contains("//")
        && !path.contains('\\')
        && !path.contains('#')
        && !path.contains('@')
        && !lower.contains("%2e")
        && !lower.contains("%2f")
        && !lower.contains("%5c")
        && path.bytes().all(|b| b.is_ascii_graphic());
    if !valid_raw {
        return Err(Invalid::Request);
    }
    let url = api_url(server, path)?;
    if url.path() != raw_path || !allowed_api_path(url.path()) {
        return Err(Invalid::Request);
    }
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| Invalid::Request)?;
    Ok((method, url))
}

/// Joins an already-validated API path onto the server origin and confirms
/// the result stayed on that origin.
pub fn api_url(server: &Url, path: &str) -> Result<Url, Invalid> {
    let joined = server.join(path).map_err(|_| Invalid::Request)?;
    if joined.origin() != server.origin() {
        return Err(Invalid::Request);
    }
    Ok(joined)
}

/// 256 random bits, base64url (43 characters).
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("the OS random number generator is unavailable");
    URL_SAFE_NO_PAD.encode(b)
}

/// RFC 7636 S256 code challenge.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Constant-time string comparison for secrets such as the OAuth state.
pub fn secure_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// What the loopback listener did with one HTTP request.
#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    /// The sign-in callback with a code whose state matched.
    Code(String),
    /// Something else (favicon, probes); ignore and keep waiting.
    Ignore,
}

/// Parses the request line of an HTTP request to the loopback listener.
/// Only `GET /callback?code=...&state=...` with the expected state is
/// accepted; a wrong state is an error so a local attacker cannot inject a code.
pub fn parse_callback(request_line: &str, expected_state: &str) -> Result<Callback, Invalid> {
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(Callback::Ignore);
    };
    if method != "GET" || !target.starts_with("/callback?") {
        return Ok(Callback::Ignore);
    }
    let url = Url::parse(&format!("http://127.0.0.1{target}")).map_err(|_| Invalid::Callback)?;
    let mut code = None;
    let mut state = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" if code.is_none() => code = Some(v.into_owned()),
            "state" if state.is_none() => state = Some(v.into_owned()),
            "code" | "state" => return Err(Invalid::Callback), // duplicated parameter
            _ => {}
        }
    }
    let (Some(code), Some(state)) = (code, state) else {
        return Err(Invalid::Callback);
    };
    if !secure_eq(&state, expected_state) {
        return Err(Invalid::Callback);
    }
    let code_ok = code.starts_with("kiln_code_") && code.len() <= 128 && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !code_ok {
        return Err(Invalid::Callback);
    }
    Ok(Callback::Code(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_accepts_https_and_loopback_http_only() {
        assert_eq!(normalize_server_url("https://kiln.example.com").unwrap().as_str(), "https://kiln.example.com/");
        assert_eq!(normalize_server_url(" https://kiln.example.com:8443/ ").unwrap().as_str(), "https://kiln.example.com:8443/");
        assert!(normalize_server_url("http://localhost:8080").is_ok());
        assert!(normalize_server_url("http://127.0.0.1:8080").is_ok());
        for bad in [
            "http://kiln.example.com",
            "ftp://kiln.example.com",
            "https://user:pass@kiln.example.com",
            "https://kiln.example.com/path",
            "https://kiln.example.com/?x=1",
            "https://kiln.example.com/#frag",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "kiln.example.com",
            "",
        ] {
            assert_eq!(normalize_server_url(bad), Err(Invalid::ServerUrl), "{bad}");
        }
    }

    #[test]
    fn api_requests_are_confined_to_the_api() {
        let server = normalize_server_url("https://kiln.example.com").unwrap();
        let (m, u) = api_target(&server, "GET", "/api/v1/orgs?limit=10").unwrap();
        assert_eq!((m.as_str(), u.as_str()), ("GET", "https://kiln.example.com/api/v1/orgs?limit=10"));
        assert!(api_target(&server, "DELETE", "/api/v1/session").is_ok());
        for (m, p) in [
            ("PATCH", "/api/v1/orgs"),
            ("TRACE", "/api/v1/orgs"),
            ("get", "/api/v1/orgs"),
            ("GET", "/healthz"),
            ("GET", "/api/v2/orgs"),
            ("POST", "/api/v1/auth/token"),
            ("GET", "/api/v1/../../admin"),
            ("GET", "/api/v1//evil.example/x"),
            ("GET", "/api/v1/x\\y"),
            ("GET", "/api/v1/x#frag"),
            ("GET", "/api/v1/x@evil.example"),
            ("GET", "/api/v1/x y"),
            ("GET", "/api/v1/x\ny"),
            ("GET", "https://evil.example/api/v1/orgs"),
            // Encoded dot-segments that URL parsing normalizes to "..".
            ("POST", "/api/v1/x/%2e%2e/auth/token"),
            ("GET", "/api/v1/x/.%2E/auth/login"),
            ("GET", "/api/v1/x/%2e./auth/token"),
            ("GET", "/api/v1/%2E%2e/%2e%2e/healthz"),
            ("GET", "/api/v1/%2e%2e/%2e%2e/metrics"),
            ("GET", "/api/v1/x/%2F%2Fevil"),
            ("GET", "/api/v1/x/%5c..%5cauth"),
            ("GET", "/api/v1/x/./auth"),
        ] {
            assert_eq!(api_target(&server, m, p).err(), Some(Invalid::Request), "{m} {p}");
        }
    }

    #[test]
    fn api_url_stays_on_the_server_origin() {
        let server = normalize_server_url("https://kiln.example.com").unwrap();
        assert_eq!(api_url(&server, "/api/v1/orgs").unwrap().as_str(), "https://kiln.example.com/api/v1/orgs");
        assert!(api_url(&server, "//evil.example/api/v1/orgs").is_err());
    }

    #[test]
    fn pkce_matches_rfc7636_vector() {
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let (a, b) = (random_token(), random_token());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        assert!(secure_eq("abc", "abc"));
        assert!(!secure_eq("abc", "abd"));
        assert!(!secure_eq("abc", "ab"));
    }

    #[test]
    fn callback_requires_matching_state_and_well_formed_code() {
        let state = "s".repeat(43);
        let code = format!("kiln_code_{}", "A".repeat(43));
        let ok = format!("GET /callback?code={code}&state={state} HTTP/1.1");
        assert_eq!(parse_callback(&ok, &state), Ok(Callback::Code(code.clone())));

        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1", &state), Ok(Callback::Ignore));
        assert_eq!(parse_callback("POST /callback?code=x&state=y HTTP/1.1", &state), Ok(Callback::Ignore));
        assert_eq!(parse_callback("garbage", &state), Ok(Callback::Ignore));

        let wrong_state = format!("GET /callback?code={code}&state={} HTTP/1.1", "t".repeat(43));
        assert_eq!(parse_callback(&wrong_state, &state), Err(Invalid::Callback));
        let dup = format!("GET /callback?code={code}&state={state}&state={state} HTTP/1.1");
        assert_eq!(parse_callback(&dup, &state), Err(Invalid::Callback));
        let bad_code = format!("GET /callback?code=%3Cscript%3E&state={state} HTTP/1.1");
        assert_eq!(parse_callback(&bad_code, &state), Err(Invalid::Callback));
        let missing = format!("GET /callback?state={state} HTTP/1.1");
        assert_eq!(parse_callback(&missing, &state), Err(Invalid::Callback));
    }
}
