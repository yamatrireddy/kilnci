// SPDX-License-Identifier: Apache-2.0
//! Kiln desktop shell (Tauri 2).
//!
//! Security model (ADR-0003, security-standards §10):
//! * The webview never sees a credential. Rust holds the short-lived access
//!   token in memory and the rotating refresh token in the OS keychain, and
//!   proxies API calls through the `api_request` command, which only reaches
//!   `/api/v1/*` on the configured server.
//! * Sign-in uses the system browser with PKCE and a one-shot loopback
//!   listener on 127.0.0.1 (RFC 8252); the state is checked in constant time.
//! * Every command is allow-listed in capabilities/main.json; no other Tauri
//!   plugin or core permission is granted to the webview.

mod security;

use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use url::Url;

use security::{api_target, api_url, normalize_server_url, parse_callback, pkce_challenge, random_token, Callback};

const KEYCHAIN_SERVICE: &str = "dev.kiln.desktop";
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RESPONSE_BYTES: usize = 10 << 20;
const MAX_REQUEST_BYTES: usize = 1 << 20;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 << 10;

/// In-memory access token, bound to the server origin that issued it so it
/// is never sent anywhere else (security review, desktop M2).
struct Access {
    origin: String,
    token: String,
    expires: Instant,
}

struct AppState {
    http: reqwest::Client,
    settings_path: PathBuf,
    server: RwLock<Option<Url>>,
    /// Held across refreshes so concurrent API calls never present the same
    /// refresh token twice (the server would treat that as theft).
    access: Mutex<Option<Access>>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Settings {
    server_url: Option<String>,
}

fn keychain(server: &Url) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, &server.origin().ascii_serialization()).map_err(|_| "the OS keychain is unavailable".to_string())
}

fn clear_refresh_token(server: &Url) {
    if let Ok(entry) = keychain(server) {
        let _ = entry.delete_credential();
    }
}

fn current_server(state: &AppState) -> Result<Url, String> {
    state.server.read().map_err(|_| "internal error".to_string())?.clone().ok_or_else(|| "no Kiln server is configured".to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

/// Reads a response body, failing once it exceeds `cap` bytes (works for
/// chunked responses too, unlike a Content-Length check).
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| "could not read the response".to_string())? {
        if out.len() + chunk.len() > cap {
            return Err("response too large".to_string());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Calls POST /api/v1/auth/token and stores the result: refresh token in the
/// keychain, access token in memory.
async fn exchange(state: &AppState, server: &Url, body: serde_json::Value, access: &mut Option<Access>) -> Result<(), String> {
    let url = api_url(server, "/api/v1/auth/token").map_err(|e| e.to_string())?;
    let resp = state.http.post(url).json(&body).send().await.map_err(|_| "could not reach the Kiln server".to_string())?;
    let status = resp.status();
    if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED {
        // The grant is dead (expired, revoked, or reuse detected).
        *access = None;
        clear_refresh_token(server);
        return Err("sign-in expired; sign in again".to_string());
    }
    if !status.is_success() {
        // 429 or 5xx: transient. Keep the refresh token and try again later.
        return Err("the Kiln server is busy; try again shortly".to_string());
    }
    let raw = read_capped(resp, MAX_TOKEN_RESPONSE_BYTES).await?;
    let t: TokenResponse = serde_json::from_slice(&raw).map_err(|_| "unexpected response from the Kiln server".to_string())?;
    // If the user switched servers while this was in flight, drop the tokens
    // rather than risk sending them to the new server.
    if current_server(state).ok().as_ref() != Some(server) {
        return Err("the Kiln server changed during sign-in; sign in again".to_string());
    }
    keychain(server)?.set_password(&t.refresh_token).map_err(|_| "could not save credentials to the OS keychain".to_string())?;
    // Refresh 30 s early so a token never expires mid-request.
    let ttl = Duration::from_secs(t.expires_in.saturating_sub(30));
    *access = Some(Access { origin: server.origin().ascii_serialization(), token: t.access_token, expires: Instant::now() + ttl });
    Ok(())
}

/// Returns a valid access token, refreshing it if needed.
async fn access_token(state: &AppState, server: &Url) -> Result<Option<String>, String> {
    let mut access = state.access.lock().await;
    let origin = server.origin().ascii_serialization();
    if let Some(a) = access.as_ref() {
        if a.origin == origin && Instant::now() < a.expires {
            return Ok(Some(a.token.clone()));
        }
    }
    let refresh = match keychain(server)?.get_password() {
        Ok(r) => r,
        Err(_) => {
            *access = None;
            return Ok(None); // not signed in
        }
    };
    exchange(state, server, serde_json::json!({ "grantType": "refresh_token", "refreshToken": refresh }), &mut access).await?;
    Ok(access.as_ref().map(|a| a.token.clone()))
}

#[tauri::command]
fn get_server_url(state: State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state.server.read().map_err(|_| "internal error")?.as_ref().map(|u| u.origin().ascii_serialization()))
}

#[tauri::command]
async fn set_server_url(state: State<'_, AppState>, url: String) -> Result<String, String> {
    let server = normalize_server_url(&url).map_err(|e| e.to_string())?;
    let origin = server.origin().ascii_serialization();
    let settings = Settings { server_url: Some(origin.clone()) };
    if let Some(dir) = state.settings_path.parent() {
        std::fs::create_dir_all(dir).map_err(|_| "could not save settings".to_string())?;
    }
    std::fs::write(&state.settings_path, serde_json::to_vec_pretty(&settings).map_err(|e| e.to_string())?).map_err(|_| "could not save settings".to_string())?;
    // A different server means different credentials.
    *state.access.lock().await = None;
    *state.server.write().map_err(|_| "internal error")? = Some(server);
    Ok(origin)
}

#[tauri::command]
async fn sign_in(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let server = current_server(&state)?;
    let verifier = random_token();
    let app_state = random_token();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| "could not start the sign-in listener".to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let mut login = api_url(&server, "/api/v1/auth/login").map_err(|e| e.to_string())?;
    login
        .query_pairs_mut()
        .append_pair("client", "desktop")
        .append_pair("redirectUri", &redirect_uri)
        .append_pair("codeChallenge", &pkce_challenge(&verifier))
        .append_pair("state", &app_state);
    open::that_detached(login.as_str()).map_err(|_| "could not open the system browser".to_string())?;

    let code = tokio::time::timeout(SIGN_IN_TIMEOUT, wait_for_code(&listener, &app_state))
        .await
        .map_err(|_| "sign-in timed out".to_string())??;
    drop(listener);

    let mut access = state.access.lock().await;
    exchange(
        &state,
        &server,
        serde_json::json!({ "grantType": "authorization_code", "code": code, "codeVerifier": verifier, "redirectUri": redirect_uri }),
        &mut access,
    )
    .await?;
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_focus();
    }
    Ok(())
}

const CALLBACK_PAGE: &str = "<!doctype html><title>Kiln</title><p>Signed in. You can close this window and return to Kiln.</p>";

/// Serves the loopback redirect until a valid callback arrives. Requests for
/// other paths are answered 404; a callback with a wrong state aborts.
async fn wait_for_code(listener: &TcpListener, expected_state: &str) -> Result<String, String> {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        // A slow, idle, or broken connection (a port scanner, another local
        // process) is dropped without aborting sign-in (security review, T-36).
        let mut buf = vec![0u8; 8192];
        let mut n = 0;
        let mut ok = true;
        while n < buf.len() {
            match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf[n..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(read)) => n += read,
                _ => {
                    ok = false;
                    break;
                }
            }
            if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        if !ok {
            continue;
        }
        let text = String::from_utf8_lossy(&buf[..n]);
        let line = text.lines().next().unwrap_or_default();
        let (status, body, result) = match parse_callback(line, expected_state) {
            Ok(Callback::Code(code)) => ("200 OK", CALLBACK_PAGE, Some(Ok(code))),
            Ok(Callback::Ignore) => ("404 Not Found", "", None),
            Err(e) => ("400 Bad Request", "<!doctype html><title>Kiln</title><p>Sign-in failed.</p>", Some(Err(e.to_string()))),
        };
        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Security-Policy: default-src 'none'\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = sock.write_all(resp.as_bytes()).await;
        let _ = sock.shutdown().await;
        if let Some(r) = result {
            return r;
        }
    }
}

#[tauri::command]
async fn sign_out(state: State<'_, AppState>) -> Result<(), String> {
    let server = current_server(&state)?;
    // Best effort: revoke the grant server-side, then forget everything locally.
    if let Ok(Some(token)) = access_token(&state, &server).await {
        if let Ok(url) = api_url(&server, "/api/v1/session") {
            let _ = state.http.delete(url).bearer_auth(token).send().await;
        }
    }
    *state.access.lock().await = None;
    clear_refresh_token(&server);
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiRequest {
    method: String,
    path: String,
    body: Option<String>,
    content_type: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse {
    status: u16,
    body: String,
    content_type: Option<String>,
}

/// The webview's only route to the network: forwards an API call to the
/// configured server with the access token attached.
#[tauri::command]
async fn api_request(state: State<'_, AppState>, request: ApiRequest) -> Result<ApiResponse, String> {
    if request.body.as_ref().is_some_and(|b| b.len() > MAX_REQUEST_BYTES) {
        return Err("request too large".to_string());
    }
    let server = current_server(&state)?;
    let (method, url) = api_target(&server, &request.method, &request.path).map_err(|e| e.to_string())?;
    let Some(token) = access_token(&state, &server).await? else {
        return Ok(ApiResponse { status: 401, body: String::new(), content_type: None });
    };
    let mut req = state.http.request(method, url).bearer_auth(token);
    if let Some(body) = request.body {
        let ct = match request.content_type.as_deref() {
            Some(ct) if ct.starts_with("application/json") => ct.to_string(),
            _ => "application/json".to_string(),
        };
        req = req.header(reqwest::header::CONTENT_TYPE, ct).body(body);
    }
    let resp = req.send().await.map_err(|_| "could not reach the Kiln server".to_string())?;
    let status = resp.status().as_u16();
    let content_type = resp.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    if resp.content_length().is_some_and(|l| l > MAX_RESPONSE_BYTES as u64) {
        return Err("response too large".to_string());
    }
    let bytes = read_capped(resp, MAX_RESPONSE_BYTES).await?;
    if status == 401 {
        *state.access.lock().await = None;
    }
    Ok(ApiResponse { status, body: String::from_utf8_lossy(&bytes).into_owned(), content_type })
}

fn load_settings(path: &PathBuf) -> Option<Url> {
    let raw = std::fs::read(path).ok()?;
    let s: Settings = serde_json::from_slice(&raw).ok()?;
    normalize_server_url(&s.server_url?).ok()
}

/// Entry point used by main.rs.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let http = reqwest::Client::builder()
        .https_only(false) // loopback http is allowed for development servers only (validated in set_server_url)
        .redirect(reqwest::redirect::Policy::none()) // never forward a bearer token to another location
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("kiln-desktop/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("failed to build HTTP client");

    tauri::Builder::default()
        .setup(move |app| {
            let settings_path = app.path().app_config_dir()?.join("settings.json");
            let server = load_settings(&settings_path);
            app.manage(AppState { http, settings_path, server: RwLock::new(server), access: Mutex::new(None) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_server_url, set_server_url, sign_in, sign_out, api_request])
        .run(tauri::generate_context!())
        .expect("error while running the Kiln desktop app");
}
