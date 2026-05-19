use anyhow::{Context, Result};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;

#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedPnk {
    pub id: Option<Uuid>,
    pub target_device_id: Uuid,
    pub wrapped_pnk: String,
    pub version: u32,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DesktopSession {
    pub email: Option<String>,
    pub image_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceKeyInfo {
    pub id: Uuid,
    pub public_hik: String,
}

#[derive(Clone)]
pub struct SupabaseClient {
    client: Client,
    url: String,
}

impl SupabaseClient {
    pub fn new() -> Result<Self> {
        // Creates a new SupabaseClient by reading environment keys and setting standard headers.
        let url = std::env::var("SUPABASE_PROJECT_URL").context("SUPABASE_PROJECT_URL must be set")?;
        let anon_key = std::env::var("SUPABASE_ANON_KEY").context("SUPABASE_ANON_KEY must be set")?;

        let mut headers = header::HeaderMap::new();
        headers.insert(
            "apikey",
            header::HeaderValue::from_str(&anon_key).context("Invalid anon key format")?,
        );
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", anon_key))
                .context("Invalid anon key format for bearer")?,
        );

        let client = Client::builder().default_headers(headers).build()?;

        Ok(Self { client, url })
    }

    pub async fn get_active_devices(&self, user_id: String) -> Result<Vec<String>> {
        // Fetches the names of all active registered devices associated with the user ID.
        let endpoint = format!("{}/rest/v1/devices", self.url);

        let response = self
            .client
            .get(&endpoint)
            .query(&[
                ("user_id", format!("eq.{}", user_id)),
                ("select", "device_name".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?;

        #[derive(Deserialize)]
        struct DeviceRecord {
            device_name: String,
        }

        let records: Vec<DeviceRecord> = response.json().await?;
        Ok(records.into_iter().map(|r| r.device_name).collect())
    }

    /// Returns all device UUIDs and public HIKs for a user — used when
    /// re-wrapping keys during PNK or HIK rotation.
    pub async fn get_devices_for_key_distribution(&self, user_id: &str) -> Result<Vec<DeviceKeyInfo>> {
        // Retrieves device UUIDs and corresponding public HIKs for all devices belonging to a user.
        let endpoint = format!("{}/rest/v1/devices", self.url);

        let response = self
            .client
            .get(&endpoint)
            .query(&[
                ("user_id", format!("eq.{}", user_id)),
                ("select", "id,public_hik".to_string()),
            ])
            .send()
            .await?
            .error_for_status()?;

        let records: Vec<DeviceKeyInfo> = response.json().await?;
        Ok(records)
    }

    pub async fn push_wrapped_pnk(
        &self,
        target_device_id: Uuid,
        owner_user_id: Uuid,
        wrapped_pnk: String,
        version: u32,
    ) -> Result<()> {
        // Pushes a wrapped PNK key structure to the key_broker database table.
        let endpoint = format!("{}/rest/v1/key_broker", self.url);
        let payload = serde_json::json!({
            "target_device_id": target_device_id,
            "owner_user_id": owner_user_id,
            "wrapped_pnk": wrapped_pnk,
            "version": version
        });
        self.client.post(&endpoint)
            .header("Prefer", "return=minimal")
            .json(&payload).send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn fetch_my_wrapped_pnks(&self, my_device_id: Uuid) -> Result<Vec<WrappedPnk>> {
        // Retrieves all wrapped PNKs currently distributed to this device.
        let endpoint = format!("{}/rest/v1/key_broker", self.url);

        let response = self
            .client
            .get(&endpoint)
            .query(&[("target_device_id", format!("eq.{}", my_device_id))])
            .send()
            .await?
            .error_for_status()?;

        let pnks: Vec<WrappedPnk> = response.json().await?;

        Ok(pnks)
    }

    pub async fn register_device(&self, user_id: String, device_name: String, public_hik: String, os_version: String) -> Result<Uuid> {
        // Upserts device info (OS version, active state, and public HIK) in the database and returns the UUID.
        let endpoint = format!("{}/rest/v1/devices", self.url);

        let check_resp = self.client.get(&endpoint)
            .query(&[("public_hik", format!("eq.{}", public_hik))])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct DeviceRecord {
            id: Uuid,
        }

        let existing: Vec<DeviceRecord> = check_resp.json().await?;
        if !existing.is_empty() {
            let device_id = existing[0].id;
            let patch_url = format!("{}?id=eq.{}", endpoint, device_id);
            self.client.patch(&patch_url)
                .json(&serde_json::json!({
                    "is_active": true,
                    "os_version": os_version,
                    "last_seen_at": Utc::now().to_rfc3339(),
                    "disconnected_at": serde_json::Value::Null
                }))
                .send().await?.error_for_status()?;
            return Ok(device_id);
        }

        let payload = serde_json::json!({
            "user_id": user_id,
            "device_name": device_name,
            "public_hik": public_hik,
            "os_version": os_version,
            "is_active": true
        });
        let resp = self.client.post(&endpoint)
            .header("Prefer", "return=representation")
            .json(&payload).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("register_device failed {}: {}", status, body);
        }

        let records: Vec<DeviceRecord> = resp.json().await?;
        let device_id = records.first()
            .ok_or_else(|| anyhow::anyhow!("No device returned from register_device"))?
            .id;
        Ok(device_id)
    }

    pub async fn set_device_status(&self, public_hik: String, is_active: bool) -> Result<()> {
        // Toggles a device's is_active presence state and records timestamp bounds in Supabase.
        let endpoint = format!("{}/rest/v1/devices", self.url);
        let patch_url = format!("{}?public_hik=eq.{}", endpoint, public_hik);

        let payload = if is_active {
            serde_json::json!({
                "is_active": true,
                "last_seen_at": Utc::now().to_rfc3339(),
                "disconnected_at": serde_json::Value::Null
            })
        } else {
            serde_json::json!({
                "is_active": false,
                "disconnected_at": Utc::now().to_rfc3339()
            })
        };

        self.client.patch(&patch_url)
            .json(&payload)
            .send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn update_last_seen(&self, public_hik: String) -> Result<()> {
        // Updates the last_seen_at heartbeat timestamp of a device in the database.
        let endpoint = format!("{}/rest/v1/devices", self.url);
        let patch_url = format!("{}?public_hik=eq.{}", endpoint, public_hik);

        self.client.patch(&patch_url)
            .json(&serde_json::json!({
                "last_seen_at": Utc::now().to_rfc3339()
            }))
            .send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn get_connections(&self, user_id: String) -> Result<Vec<String>> {
        // Fetches active connected user relationships for the specified user account.
        let endpoint = format!("{}/rest/v1/connections", self.url);
        let or_filter = format!("(initiator_user_id.eq.{},target_user_id.eq.{})", user_id, user_id);

        let response = self.client.get(&endpoint)
            .query(&[
                ("or", or_filter),
                ("status", "eq.accepted".to_string()),
                ("select", "id".to_string()),
            ])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct ConnRecord {
            id: Uuid
        }
        let records: Vec<ConnRecord> = response.json().await?;
        Ok(records.into_iter().map(|r| r.id.to_string()).collect())
    }

    pub async fn get_latest_key_version(&self, device_id: Uuid) -> Result<Option<u32>> {
        // Retrieves the highest version tag of the wrapped PNK currently stored in the key_broker.
        let endpoint = format!("{}/rest/v1/key_broker", self.url);

        let response = self.client.get(&endpoint)
            .query(&[
                ("target_device_id", format!("eq.{}", device_id)),
                ("select", "version".to_string()),
                ("order", "version.desc".to_string()),
                ("limit", "1".to_string()),
            ])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct VersionRecord {
            version: u32,
        }

        let records: Vec<VersionRecord> = response.json().await?;
        Ok(records.first().map(|r| r.version))
    }

    pub async fn check_key_sync_needed(&self, device_id: Uuid, local_version: u32) -> Result<bool> {
        // Compares active local key versions against the latest key broker version.
        match self.get_latest_key_version(device_id).await? {
            Some(latest) => Ok(latest > local_version),
            None => Ok(false),
        }
    }

    pub async fn update_device_hik(&self, device_id: Uuid, new_public_hik: &str, hik_version: u32) -> Result<()> {
        // Rotates and updates the public HIK and version of the device inside the database.
        let endpoint = format!("{}/rest/v1/devices", self.url);
        let patch_url = format!("{}?id=eq.{}", endpoint, device_id);
        let now = Utc::now().to_rfc3339();

        self.client.patch(&patch_url)
            .json(&serde_json::json!({
                "public_hik": new_public_hik,
                "hik_version": hik_version,
                "last_seen_at": now.clone(),
                "last_key_rotation": now
            }))
            .send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn fetch_wrapped_pnks_for_device(&self, device_id: Uuid) -> Result<Vec<WrappedPnk>> {
        // Fetches all wrapped PNK envelopes targeted to a specific device, sorted by descending version.
        let endpoint = format!("{}/rest/v1/key_broker", self.url);

        let response = self.client.get(&endpoint)
            .query(&[
                ("target_device_id", format!("eq.{}", device_id)),
                ("order", "version.desc".to_string()),
            ])
            .send().await?.error_for_status()?;

        let pnks: Vec<WrappedPnk> = response.json().await?;
        Ok(pnks)
    }

    pub async fn get_desktop_session(&self, user_id: &str) -> Result<Option<DesktopSession>> {
        // Fetches the user session from the public.desktop_sessions table if it exists.
        let endpoint = format!("{}/rest/v1/desktop_sessions", self.url);
        let response = self.client.get(&endpoint)
            .query(&[
                ("user_id", format!("eq.{}", user_id)),
                ("select", "email,image_url".to_string()),
            ])
            .send().await?
            .error_for_status()?;

        let mut records: Vec<DesktopSession> = response.json().await?;
        Ok(records.pop())
    }
}
