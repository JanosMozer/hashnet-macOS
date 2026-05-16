use anyhow::{Context, Result};
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedPnk {
    pub id: Option<Uuid>,
    pub target_device_id: Uuid,
    pub wrapped_pnk: String,
    pub version: u32,
    pub created_at: Option<String>,
}

pub struct SupabaseClient {
    client: Client,
    url: String,
}

impl SupabaseClient {
    pub fn new() -> Result<Self> {
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

    pub async fn push_wrapped_pnk(
        &self,
        target_device_id: Uuid,
        owner_user_id: Uuid,
        wrapped_pnk: String,
        version: u32,
    ) -> Result<()> {
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

    pub async fn register_device(&self, user_id: String, device_name: String, public_hik: String) -> Result<()> {
        let endpoint = format!("{}/rest/v1/devices", self.url);

        // Check if device already exists for this HIK
        let check_resp = self.client.get(&endpoint)
            .query(&[("public_hik", format!("eq.{}", public_hik))])
            .send().await?.error_for_status()?;
        
        let existing: Vec<serde_json::Value> = check_resp.json().await?;
        if !existing.is_empty() {
            // Already registered, just update is_active
            if let Some(id) = existing[0].get("id") {
                let patch_url = format!("{}?id=eq.{}", endpoint, id.as_str().unwrap_or_default());
                self.client.patch(&patch_url)
                    .json(&serde_json::json!({ "is_active": true }))
                    .send().await?.error_for_status()?;
            }
            return Ok(());
        }

        let payload = serde_json::json!({
            "user_id": user_id,
            "device_name": device_name,
            "public_hik": public_hik,
            "is_active": true
        });
        let resp = self.client.post(&endpoint)
            .header("Prefer", "return=minimal")
            .json(&payload).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("register_device failed {}: {}", status, body);
        }
        Ok(())
    }

    pub async fn set_device_status(&self, public_hik: String, is_active: bool) -> Result<()> {
        let endpoint = format!("{}/rest/v1/devices", self.url);
        let patch_url = format!("{}?public_hik=eq.{}", endpoint, public_hik);
        
        self.client.patch(&patch_url)
            .json(&serde_json::json!({ "is_active": is_active }))
            .send().await?.error_for_status()?;
        Ok(())
    }

    pub async fn get_connections(&self, user_id: String) -> Result<Vec<String>> {
        let endpoint = format!("{}/rest/v1/connections", self.url);
        // PostgREST or() filter syntax
        let or_filter = format!("(initiator_user_id.eq.{},target_user_id.eq.{})", user_id, user_id);
        let response = self.client.get(&endpoint)
            .query(&[
                ("or", or_filter.as_str()),
                ("status", "eq.accepted"),
                ("select", "id"),
            ])
            .send().await?.error_for_status()?;

        #[derive(Deserialize)]
        struct ConnRecord { id: Uuid }
        let records: Vec<ConnRecord> = response.json().await?;
        Ok(records.into_iter().map(|r| r.id.to_string()).collect())
    }
}
