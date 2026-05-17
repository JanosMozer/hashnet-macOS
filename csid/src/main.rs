use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::{URL_SAFE_NO_PAD as Base64Url, STANDARD as Base64}, Engine};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Deserialize;
use tracing::{error, info};

use csi_core::broker::SupabaseClient;
use csi_core::crypto::{HardwareIdentity, PersonalNetworkKey};
use csi_ipc::{IpcRequest, IpcResponse};
use x25519_dalek::PublicKey as X25519PublicKey;

mod logging;

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
    device_id: Option<uuid::Uuid>,
    key_version: u32,
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
    if let Err(e) = logging::init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        return Err(e);
    }
    info!("Starting csid daemon");

    let identity = HardwareIdentity::load_or_generate()
        .map_err(|e| anyhow::anyhow!("Failed to load hardware identity: {}", e))?;

    let broker = match SupabaseClient::new() {
        Ok(client) => Some(client),
        Err(e) => {
            error!("Warning: Failed to initialize Supabase client: {}", e);
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
        device_id: None,
        key_version: 1,
    }));

    // Spawn background heartbeat loop (Phase 2)
    let state_heartbeat = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let (broker, hik, logged_in) = {
                let s = state_heartbeat.read().await;
                (s.broker.clone(), s.identity.export_public_hik(), s.logged_in_user.is_some())
            };
            if logged_in {
                if let Some(client) = broker {
                    // Update device's last_seen_at timestamp
                    if let Err(e) = client.update_last_seen(hik).await {
                        error!("Heartbeat error updating last_seen_at: {}", e);
                    }
                }
            }
        }
    });

    // Periodic PNK auto-rotation every 24 hours
    let state_rotation = state.clone();
    tokio::spawn(async move {
        const PNK_ROTATION_INTERVAL_SECS: u64 = 86_400; // 24 hours
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(PNK_ROTATION_INTERVAL_SECS)).await;
            let (broker, user_id, hik_secret, current_version) = {
                let s = state_rotation.read().await;
                (
                    s.broker.clone(),
                    s.logged_in_user.clone(),
                    s.identity.secret().clone(),
                    s.key_version,
                )
            };
            if let (Some(broker), Some(uid)) = (broker, user_id) {
                let new_pnk = PersonalNetworkKey::new_random();
                let new_version = current_version.saturating_add(1);
                match broker.get_devices_for_key_distribution(&uid).await {
                    Ok(devices) => {
                        let mut ok = true;
                        for device in &devices {
                            if let Ok(target_pub) = parse_public_hik(&device.public_hik) {
                                if let Ok(wrapped) = new_pnk.wrap(&target_pub, &hik_secret) {
                                    let b64 = Base64.encode(&wrapped);
                                    if let Err(e) = broker.push_wrapped_pnk(
                                        device.id,
                                        uid.parse().unwrap_or_default(),
                                        b64,
                                        new_version,
                                    ).await {
                                        error!("auto-rotation push error: {}", e);
                                        ok = false;
                                    }
                                }
                            }
                        }
                        if ok {
                            let mut s = state_rotation.write().await;
                            s.pnk = Some(new_pnk);
                            s.key_version = new_version;
                        }
                    }
                    Err(e) => error!("auto-rotation device fetch error: {}", e),
                }
            }
        }
    });

    let socket_path = "/tmp/csi.sock";

    if std::fs::metadata(socket_path).is_ok() {
        std::fs::remove_file(socket_path).context("Failed to remove existing socket file")?;
    }

    let listener = UnixListener::bind(socket_path).context("Failed to bind socket")?;

    // Set permissions to 0600 (owner read/write only)
    std::fs::set_permissions(socket_path, Permissions::from_mode(0o600))
        .context("Failed to set socket permissions")?;

    

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state_clone = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state_clone).await {
                        error!("Client error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
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

    info!("Waiting for OAuth callback on http://127.0.0.1:{}", OAUTH_CALLBACK_PORT);

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

    info!("Exchanging code for token...");
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
    info!("Received token data: {:?}", token_data);

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
    <h1> Login Successful</h1>
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

fn parse_public_hik(b64: &str) -> anyhow::Result<X25519PublicKey> {
    let bytes = Base64.decode(b64)?;
    if bytes.len() != 32 {
        anyhow::bail!("invalid HIK length: {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(X25519PublicKey::from(arr))
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
                        let (broker, key_version) = {
                            let mut s = state_clone.write().await;
                            s.oauth_listening = false;
                            s.logged_in_user = Some(data.user_id.clone());
                            s.user_email = data.email;
                            s.user_image = data.image_url;
                            (s.broker.clone(), s.key_version)
                        };

                        if let Some(broker) = broker {
                            let hostname = gethostname::gethostname().to_string_lossy().to_string();
                            let hik = {
                                let s = state_clone.read().await;
                                s.identity.export_public_hik()
                            };

                            // Get macOS version formatted as "macOS X.Y.Z"
                            let os_version = std::process::Command::new("sw_vers")
                                .arg("-productVersion")
                                .output()
                                .map(|o| format!("macOS {}", String::from_utf8_lossy(&o.stdout).trim()))
                                .unwrap_or_else(|_| "macOS".to_string());

                            // Register device and get its UUID
                            match broker.register_device(data.user_id.clone(), hostname, hik, os_version).await {
                                Ok(device_id) => {
                                    // Check if newer keys are available for sync
                                    if let Ok(needs_sync) = broker.check_key_sync_needed(device_id, key_version).await {
                                        if needs_sync {
                                            error!("Key sync needed on login");
                                            // TODO: Implement actual key sync
                                        }
                                    }
                                    let mut s = state_clone.write().await;
                                    s.device_id = Some(device_id);
                                }
                                Err(e) => {
                                    error!("Failed to register device: {}", e);
                                }
                            }
                        }

                        let mut s = state_clone.write().await;
                        s.pnk = Some(PersonalNetworkKey::new_random());
                    }
                    Err(e) => {
                        error!("OAuth error: {}", e);
                        let mut s = state_clone.write().await;
                        s.oauth_listening = false;
                    }
                }
            });

            IpcResponse::Success
        }
        IpcRequest::SyncKeys => {
            let (broker, device_id) = {
                let s = state.read().await;
                (s.broker.clone(), s.device_id)
            };

            if broker.is_none() || device_id.is_none() {
                return IpcResponse::Error("Not ready for sync".into());
            }

            let broker = broker.unwrap();
            let device_id = device_id.unwrap();

            match broker.fetch_wrapped_pnks_for_device(device_id).await {
                Ok(wrapped_pnks) => {
                    if wrapped_pnks.is_empty() {
                        return IpcResponse::Error("No keys available for sync".into());
                    }

                    let latest = &wrapped_pnks[0];
                    let hik = {
                        let s = state.read().await;
                        s.identity.clone()
                    };

                    match csi_core::crypto::PersonalNetworkKey::unwrap(
                        Base64.decode(&latest.wrapped_pnk)
                            .unwrap_or_default().as_ref(),
                        hik.public_key(),
                        hik.secret(),
                    ) {
                        Ok(_synced_key) => {
                            let mut s = state.write().await;
                            s.key_version = latest.version;
                            s.pnk = Some(_synced_key);
                            IpcResponse::Success
                        }
                        Err(e) => {
                            error!("Failed to unwrap key: {}", e);
                            IpcResponse::Error("Key unwrap failed".into())
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to fetch wrapped PNKs: {}", e);
                    IpcResponse::Error("Failed to fetch keys".into())
                }
            }
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
            let (broker, user_id, hik_secret, current_version) = {
                let s = state.read().await;
                (
                    s.broker.clone(),
                    s.logged_in_user.clone(),
                    s.identity.secret().clone(),
                    s.key_version,
                )
            };

            if let (Some(broker), Some(uid)) = (broker, user_id) {
                let new_pnk = PersonalNetworkKey::new_random();
                let new_version = current_version.saturating_add(1);

                match broker.get_devices_for_key_distribution(&uid).await {
                    Ok(devices) => {
                        let mut push_errors = 0usize;
                        for device in &devices {
                            match parse_public_hik(&device.public_hik) {
                                Ok(target_pub) => {
                                    match new_pnk.wrap(&target_pub, &hik_secret) {
                                        Ok(wrapped) => {
                                            let b64 = Base64.encode(&wrapped);
                                            if let Err(e) = broker.push_wrapped_pnk(
                                                device.id,
                                                uid.parse().unwrap_or_default(),
                                                b64,
                                                new_version,
                                            ).await {
                                                error!("push_wrapped_pnk error for {}: {}", device.id, e);
                                                push_errors += 1;
                                            }
                                        }
                                        Err(e) => {
                                            error!("wrap error for {}: {}", device.id, e);
                                            push_errors += 1;
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("bad HIK for device {}: {}", device.id, e);
                                    push_errors += 1;
                                }
                            }
                        }
                        if push_errors > 0 {
                            return IpcResponse::Error(format!("PNK rotated but {} device(s) failed", push_errors));
                        }
                        let mut s = state.write().await;
                        s.pnk = Some(new_pnk);
                        s.key_version = new_version;
                        IpcResponse::Success
                    }
                    Err(e) => {
                        error!("Failed to fetch devices for PNK rotation: {}", e);
                        IpcResponse::Error("Failed to fetch devices for rotation".into())
                    }
                }
            } else {
                IpcResponse::Error("Not logged in".into())
            }
        }
        IpcRequest::RotateHik => {
            let (broker, user_id) = {
                let s = state.read().await;
                (s.broker.clone(), s.logged_in_user.clone())
            };

            if let (Some(broker), Some(uid)) = (broker, user_id) {
                // Rotate the HIK — persists new key to device-bound Keychain
                let (new_hik_pub, new_hik_secret, hik_version) = {
                    let mut s = state.write().await;
                    match s.identity.rotate() {
                        Ok(_old_pub) => {
                            let pub_key = *s.identity.public_key();
                            let sec_key = s.identity.secret().clone();
                            let ver = s.identity.version;
                            (pub_key, sec_key, ver)
                        }
                        Err(e) => {
                            error!("HIK rotation failed: {}", e);
                            return IpcResponse::Error(format!("HIK rotation failed: {}", e));
                        }
                    }
                };

                let new_hik_b64 = Base64.encode(new_hik_pub.as_bytes());

                // Update this device's public_hik in the database
                if let Some(device_id) = { state.read().await.device_id } {
                    if let Err(e) = broker.update_device_hik(device_id, &new_hik_b64, hik_version).await {
                        error!("Failed to update HIK in DB: {}", e);
                        return IpcResponse::Error("DB update for HIK failed".into());
                    }
                }

                // Re-wrap and redistribute the current PNK under the new HIK
                let pnk_version = state.read().await.key_version;
                let pnk_bytes = {
                    let s = state.read().await;
                    s.pnk.as_ref().map(|p| p.0)
                };

                if let Some(bytes) = pnk_bytes {
                    let current_pnk = PersonalNetworkKey(bytes);
                    if let Ok(devices) = broker.get_devices_for_key_distribution(&uid).await {
                        for device in &devices {
                            if let Ok(target_pub) = parse_public_hik(&device.public_hik) {
                                if let Ok(wrapped) = current_pnk.wrap(&target_pub, &new_hik_secret) {
                                    let b64 = Base64.encode(&wrapped);
                                    let _ = broker.push_wrapped_pnk(
                                        device.id,
                                        uid.parse().unwrap_or_default(),
                                        b64,
                                        pnk_version,
                                    ).await;
                                }
                            }
                        }
                    }
                }

                IpcResponse::Success
            } else {
                IpcResponse::Error("Not logged in".into())
            }
        }
        IpcRequest::Login { user_id } => {
            let (broker, key_version) = {
                let mut s = state.write().await;
                s.logged_in_user = Some(user_id.clone());
                (s.broker.clone(), s.key_version)
            };

            if let Some(broker) = broker {
                let hostname = gethostname::gethostname().to_string_lossy().to_string();
                let hik = {
                    let s = state.read().await;
                    s.identity.export_public_hik()
                };

                let os_version = std::process::Command::new("sw_vers")
                    .arg("-productVersion")
                    .output()
                    .map(|o| format!("macOS {}", String::from_utf8_lossy(&o.stdout).trim()))
                    .unwrap_or_else(|_| "macOS".to_string());

                // Register device and get its UUID
                match broker.register_device(user_id.clone(), hostname, hik, os_version).await {
                    Ok(device_id) => {
                        // Check if newer keys are available for sync
                        if let Ok(needs_sync) = broker.check_key_sync_needed(device_id, key_version).await {
                            if needs_sync {
                                error!("Key sync needed on login");
                                // TODO: Implement actual key sync
                            }
                        }
                        let mut s = state.write().await;
                        s.device_id = Some(device_id);
                    }
                    Err(e) => {
                        error!("Failed to register device: {}", e);
                    }
                }
            }

            {
                let mut s = state.write().await;
                s.pnk = Some(PersonalNetworkKey::new_random());
            }
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
            s.device_id = None;
            IpcResponse::Success
        }
    }
}
