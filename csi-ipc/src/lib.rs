use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileInfo {
    pub enc_path: String,
    pub original_name: String,
    pub size_bytes: u64,
    pub encrypted_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    GetStatus,
    SyncKeys,
    AcceptInvite { target_user_id: String },
    RotatePnk,
    RotateHik,
    RotateKeys,
    Login { user_id: String },
    StartOAuthFlow,
    GetNetworkDevices,
    GetConnections,
    GetFiles,
    OpenFile { enc_path: String },
    Logout,
    EncryptFile { file_path: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Success,
    Error(String),
    Status {
        hostname: String,
        is_active: bool,
        state: String,
        hik: String,
        email: Option<String>,
        image_url: Option<String>
    },
    NetworkDevices(Vec<String>),
    Connections(Vec<String>),
    Files(Vec<FileInfo>),
    OAuthUrl(String),
    EncryptedFile { path: String, manifest_entry: String },
}
