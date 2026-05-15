use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    GetStatus,
    SyncKeys,
    AcceptInvite { target_user_id: String },
    RotatePnk,
    Login { user_id: String },
    StartOAuthFlow,
    GetNetworkDevices,
    GetConnections,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Success,
    Error(String),
    Status { hostname: String, is_active: bool, state: String, hik: String },
    NetworkDevices(Vec<String>),
    Connections(Vec<String>),
    OAuthUrl(String),
}
