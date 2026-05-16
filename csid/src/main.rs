use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as Base64Url, Engine};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Deserialize;

use csi_core::broker::SupabaseClient;
use csi_core::crypto::{HardwareIdentity, PersonalNetworkKey};
use csi_ipc::{IpcRequest, IpcResponse};

const OAUTH_CALLBACK_PORT: u16 = 14555;
const AUTH_BASE_URL: &str = "https://bluehashsecurity.com/api/auth/authorize";
const TOKEN_URL: &str = "https://bluehashsecurity.com/api/auth/token";
const CLIENT_ID: &str = "bluehash-desktop";
const REDIRECT_URI: &str = "http://127.0.0.1:14555";

struct DaemonState {
    identity: HardwareIdentity,
    pnk: Option<PersonalNetworkKey>,
    broker: Option<SupabaseClient>,
    logged_in_user: Option<String>,
    user_email: Option<String>,
    user_image: Option<String>,
    oauth_listening: bool,
}

#[derive(Deserialize, Debug)]
struct TokenResponse {
    user_id: String,
    email: Option<String>,
    image_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    println!("Starting csid...");

    let identity = HardwareIdentity::load_or_generate().context("Failed to load HardwareIdentity")?;

    let broker = match SupabaseClient::new() {
        Ok(client) => Some(client),
        Err(e) => {
            eprintln!("Warning: Failed to initialize Supabase client: {}", e);
            None
        }
    };

    let state = Arc::new(RwLock::new(DaemonState {
        identity,
        pnk: None,
        broker,
        logged_in_user: None,
        user_email: None,
        user_image: None,
        oauth_listening: false,
    }));

    let socket_path = "/tmp/csi.sock";

    if std::fs::metadata(socket_path).is_ok() {
        std::fs::remove_file(socket_path).context("Failed to remove existing socket file")?;
    }

    let listener = UnixListener::bind(socket_path).context("Failed to bind socket")?;

    // Set permissions to 0600 (owner read/write only)
    std::fs::set_permissions(socket_path, Permissions::from_mode(0o600))
        .context("Failed to set socket permissions")?;

    println!("Listening for IPC on {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state_clone = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state_clone).await {
                        eprintln!("Client error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_client(mut stream: UnixStream, state: Arc<RwLock<DaemonState>>) -> Result<()> {
    let mut buf = vec![0u8; 4096];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break; // Connection closed
        }

        let req_str = std::str::from_utf8(&buf[..n])?;

        for line in req_str.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let response = if let Ok(req) = serde_json::from_str::<IpcRequest>(line) {
                process_request(req, &state).await
            } else {
                IpcResponse::Error("Failed to parse request JSON".into())
            };

            let mut resp_json = serde_json::to_string(&response)?;
            resp_json.push('\n');
            stream.write_all(resp_json.as_bytes()).await?;
        }
    }

    Ok(())
}

fn generate_pkce() -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut verifier_bytes);
    let verifier = Base64Url.encode(verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge_bytes = hasher.finalize();
    let challenge = Base64Url.encode(challenge_bytes);

    (verifier, challenge)
}

async fn wait_for_oauth_code(code_verifier: String) -> Result<TokenResponse> {
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    let listener = TcpListener::bind(format!("127.0.0.1:{}", OAUTH_CALLBACK_PORT))
        .await
        .context("Failed to bind OAuth callback port. Kill any stale process on :14555 and retry.")?;

    println!("[csid] Waiting for OAuth callback on http://127.0.0.1:{}", OAUTH_CALLBACK_PORT);

    let (stream, _) = timeout(Duration::from_secs(300), listener.accept())
        .await
        .context("OAuth login timed out after 5 minutes")??;
    let mut stream = tokio::io::BufReader::new(stream);

    let mut request_line = String::new();
    tokio::io::AsyncBufReadExt::read_line(&mut stream, &mut request_line).await?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    let query_str = path.splitn(2, '?').nth(1).unwrap_or("");
    let params: HashMap<String, String> = query_str
        .split('&')
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            Some((
                parts.next()?.to_string(),
                urlencoding::decode(parts.next().unwrap_or("")).ok()?.into_owned(),
            ))
        })
        .collect();

    let code = params
        .get("code")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No code in OAuth callback URL"))?;

    println!("[csid] Exchanging code for token...");
    let client = reqwest::Client::new();
    let resp = client
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", &code_verifier),
        ])
        .send()
        .await?
        .error_for_status()?;

    let token_data: TokenResponse = resp.json().await?;
    println!("[csid] Received token data: {:?}", token_data);

    let inner_stream = stream.into_inner();
    let mut inner_stream = inner_stream;

    let html_body = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login Successful</title>
  <style>
    body { font-family: -apple-system, sans-serif; display: flex; justify-content: center;
           align-items: center; height: 100vh; margin: 0; background: #0f0f0f; color: #fff; }
    .card { text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <h1>✅ Login Successful</h1>
    <p>You can close this tab.</p>
  </div>
  <script>setTimeout(() => window.close(), 2000);</script>
</body>
</html>"#;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html_body.len(),
        html_body
    );
    inner_stream.write_all(response.as_bytes()).await?;

    Ok(token_data)
}

async fn process_request(req: IpcRequest, state: &Arc<RwLock<DaemonState>>) -> IpcResponse {
    match req {
        IpcRequest::GetStatus => {
            let s = state.read().await;
            let status = if s.pnk.is_some() {
                "Ready (PNK loaded)"
            } else {
                "Waiting for PNK"
            };

            let hostname = gethostname::gethostname().to_string_lossy().to_string();
            let is_active = s.logged_in_user.is_some();

            IpcResponse::Status {
                hostname,
                is_active,
                state: status.to_string(),
                hik: s.identity.export_public_hik(),
                email: s.user_email.clone(),
                image_url: s.user_image.clone(),
            }
        }
        IpcRequest::StartOAuthFlow => {
            {
                let mut s = state.write().await;
                if s.oauth_listening {
                    return IpcResponse::Error("Login already in progress. Check your browser.".into());
                }
                s.oauth_listening = true;
            }

            let state_clone = state.clone();
            let (verifier, challenge) = generate_pkce();

            let url = format!(
                "{}?client_id={}&response_type=code&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
                AUTH_BASE_URL,
                CLIENT_ID,
                urlencoding::encode(REDIRECT_URI),
                challenge
            );

            if let Err(e) = open::that(&url) {
                let mut s = state_clone.write().await;
                s.oauth_listening = false;
                return IpcResponse::Error(format!("Failed to open browser: {}", e));
            }

            tokio::spawn(async move {
                match wait_for_oauth_code(verifier).await {
                    Ok(data) => {
                        let mut s = state_clone.write().await;
                        s.oauth_listening = false;
                        s.logged_in_user = Some(data.user_id.clone());
                        s.user_email = data.email;
                        s.user_image = data.image_url;
                        if let Some(broker) = &s.broker {
                            let hostname = gethostname::gethostname().to_string_lossy().to_string();
                            let hik = s.identity.export_public_hik();
                            let _ = broker.register_device(data.user_id.clone(), hostname, hik).await;
                        }
                        s.pnk = Some(PersonalNetworkKey::new_random());
                    }
                    Err(e) => {
                        eprintln!("[csid] OAuth error: {}", e);
                        let mut s = state_clone.write().await;
                        s.oauth_listening = false;
                    }
                }
            });

            IpcResponse::Success
        }
        IpcRequest::SyncKeys => {
            let s = state.read().await;
            if s.broker.is_none() {
                return IpcResponse::Error("Broker not initialized".into());
            }
            IpcResponse::Success
        }
        IpcRequest::AcceptInvite { target_user_id: _ } => {
            let s = state.read().await;
            if s.broker.is_none() {
                return IpcResponse::Error("Broker not initialized".into());
            }
            if s.pnk.is_none() {
                return IpcResponse::Error("No PNK available to share".into());
            }
            IpcResponse::Success
        }
        IpcRequest::RotatePnk => {
            let mut s = state.write().await;
            s.pnk = Some(PersonalNetworkKey::new_random());
            IpcResponse::Success
        }
        IpcRequest::Login { user_id } => {
            let mut s = state.write().await;
            s.logged_in_user = Some(user_id.clone());
            if let Some(broker) = &s.broker {
                let hostname = gethostname::gethostname().to_string_lossy().to_string();
                let hik = s.identity.export_public_hik();
                let _ = broker.register_device(user_id.clone(), hostname, hik).await;
            }
            s.pnk = Some(PersonalNetworkKey::new_random());
            IpcResponse::Success
        }
        IpcRequest::GetNetworkDevices => {
            let s = state.read().await;
            if let (Some(broker), Some(uid)) = (&s.broker, s.logged_in_user.clone()) {
                if let Ok(devs) = broker.get_active_devices(uid).await {
                    return IpcResponse::NetworkDevices(devs);
                }
            }
            IpcResponse::Error("Failed to fetch devices".into())
        }
        IpcRequest::GetConnections => {
            let s = state.read().await;
            if let (Some(broker), Some(uid)) = (&s.broker, s.logged_in_user.clone()) {
                if let Ok(conns) = broker.get_connections(uid).await {
                    return IpcResponse::Connections(conns);
                }
            }
            IpcResponse::Error("Failed to fetch connections".into())
        }
        IpcRequest::Logout => {
            let mut s = state.write().await;
            if let Some(broker) = &s.broker {
                let hik = s.identity.export_public_hik();
                let _ = broker.set_device_status(hik, false).await;
            }
            s.logged_in_user = None;
            s.user_email = None;
            s.user_image = None;
            s.pnk = None;
            IpcResponse::Success
        }
    }
}
