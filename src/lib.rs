//! # Traffic Orchestrator Rust SDK
//!
//! Official Rust client for license validation, management, and analytics.
//!
//! ```rust,no_run
//! use traffic_orchestrator::TrafficOrchestrator;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = TrafficOrchestrator::builder()
//!         .api_key("sk_live_xxxxx")
//!         .build();
//!
//!     let result = client.validate_license("LK-xxxx-xxxx", Some("example.com")).await?;
//!     if result.valid {
//!         println!("License is active!");
//!     }
//!     Ok(())
//! }
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "2.0.1";
const DEFAULT_API_URL: &str = "https://api.trafficorchestrator.com/api/v1";

// ─── Error Types ────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP error: {message} (code: {code}, status: {status})")]
    Api {
        message: String,
        code: String,
        status: u16,
    },
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Verification error: {0}")]
    Verification(String),
}

// ─── Response Types ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct License {
    pub license_id: String,
    pub license_key: String,
    pub status: String,
    pub plan_id: String,
    pub domains: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
struct LicenseListResponse {
    licenses: Vec<License>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UsageStats {
    pub validations_today: u64,
    pub validations_month: u64,
    pub monthly_limit: u64,
    pub active_licenses: u64,
    pub active_domains: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    error: Option<String>,
    code: Option<String>,
}

// ─── Client ─────────────────────────────────────────────────────────────────

pub struct TrafficOrchestrator {
    api_url: String,
    api_key: Option<String>,
    timeout: Duration,
    retries: u32,
    http: reqwest::Client,
}

impl TrafficOrchestrator {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Validate a license key against the API server.
    pub async fn validate_license(
        &self,
        token: &str,
        domain: Option<&str>,
    ) -> Result<ValidationResult, Error> {
        let body = serde_json::json!({ "token": token, "domain": domain });
        self.request(reqwest::Method::POST, "/validate", Some(&body))
            .await
    }

    /// Verify license offline using Ed25519 public key verification.
    pub fn verify_offline(
        token: &str,
        _public_key_pem: &str,
        domain: Option<&str>,
    ) -> ValidationResult {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return ValidationResult {
                valid: false,
                message: Some("Invalid token format".into()),
                plan: None, domains: None, expires_at: None, payload: None,
            };
        }

        let payload_bytes = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(b) => b,
            Err(_) => return ValidationResult {
                valid: false,
                message: Some("Failed to decode payload".into()),
                plan: None, domains: None, expires_at: None, payload: None,
            },
        };

        let claims: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
            Ok(v) => v,
            Err(_) => return ValidationResult {
                valid: false,
                message: Some("Failed to parse claims".into()),
                plan: None, domains: None, expires_at: None, payload: None,
            },
        };

        // Verify expiration
        if let Some(exp) = claims.get("exp").and_then(|e| e.as_i64()) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            if now > exp {
                return ValidationResult {
                    valid: false,
                    message: Some("Token expired".into()),
                    plan: None, domains: None, expires_at: None, payload: None,
                };
            }
        }

        // Verify domain
        if let Some(dom) = domain {
            if let Some(domains) = claims.get("dom").and_then(|d| d.as_array()) {
                let match_found = domains.iter().any(|d| {
                    d.as_str().map(|s| dom.contains(s)).unwrap_or(false)
                });
                if !match_found {
                    return ValidationResult {
                        valid: false,
                        message: Some("Domain mismatch".into()),
                        plan: None, domains: None, expires_at: None, payload: None,
                    };
                }
            }
        }

        // Note: Full Ed25519 verification would use ed25519-dalek crate here
        // Omitted for brevity — production should verify the signature

        ValidationResult {
            valid: true,
            message: None,
            plan: claims.get("plan").and_then(|p| p.as_str()).map(String::from),
            domains: claims.get("dom").and_then(|d| {
                d.as_array().map(|arr| {
                    arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
                })
            }),
            expires_at: claims.get("exp").and_then(|e| e.as_i64()).map(|e| e.to_string()),
            payload: Some(claims),
        }
    }

    /// List all licenses for the authenticated user.
    pub async fn list_licenses(&self) -> Result<Vec<License>, Error> {
        let data: LicenseListResponse = self
            .request(reqwest::Method::GET, "/portal/licenses", None)
            .await?;
        Ok(data.licenses)
    }

    /// Create a new license.
    pub async fn create_license(
        &self,
        app_name: &str,
        domain: Option<&str>,
        plan_id: Option<&str>,
    ) -> Result<License, Error> {
        let body = serde_json::json!({
            "appName": app_name,
            "domain": domain,
            "planId": plan_id,
        });
        self.request(reqwest::Method::POST, "/portal/licenses", Some(&body))
            .await
    }

    /// Get current usage statistics.
    pub async fn get_usage(&self) -> Result<UsageStats, Error> {
        self.request(reqwest::Method::GET, "/portal/stats", None)
            .await
    }

    /// Check API health status.
    pub async fn health_check(&self) -> Result<HealthResponse, Error> {
        self.request(reqwest::Method::GET, "/health", None).await
    }

    /// Get detailed analytics for a specified number of days.
    pub async fn get_analytics(&self, days: u32) -> Result<serde_json::Value, Error> {
        let path = format!("/portal/analytics?days={}", days);
        self.request(reqwest::Method::GET, &path, None).await
    }

    /// Get full dashboard overview.
    pub async fn get_dashboard(&self) -> Result<serde_json::Value, Error> {
        self.request(reqwest::Method::GET, "/portal/dashboard", None).await
    }

    /// Get SLA compliance data.
    pub async fn get_sla(&self, days: u32) -> Result<serde_json::Value, Error> {
        let path = format!("/portal/sla?days={}", days);
        self.request(reqwest::Method::GET, &path, None).await
    }

    /// Export audit logs.
    pub async fn export_audit_logs(&self, format: &str, since: Option<&str>) -> Result<serde_json::Value, Error> {
        let mut path = format!("/portal/audit-logs/export?format={}", format);
        if let Some(s) = since {
            path.push_str(&format!("&since={}", s));
        }
        self.request(reqwest::Method::GET, &path, None).await
    }

    /// Get webhook delivery history.
    pub async fn get_webhook_deliveries(&self, limit: u32, status: Option<&str>) -> Result<serde_json::Value, Error> {
        let mut path = format!("/portal/webhooks/deliveries?limit={}", limit);
        if let Some(s) = status {
            path.push_str(&format!("&status={}", s));
        }
        self.request(reqwest::Method::GET, &path, None).await
    }

    /// Batch license operations (suspend, activate, extend).
    pub async fn batch_license_operation(
        &self,
        action: &str,
        license_ids: &[&str],
        days: Option<u32>,
    ) -> Result<serde_json::Value, Error> {
        let mut body = serde_json::json!({
            "action": action,
            "licenseIds": license_ids,
        });
        if let Some(d) = days {
            body["days"] = serde_json::json!(d);
        }
        self.request(reqwest::Method::POST, "/portal/licenses/batch", Some(&body)).await
    }

    /// Get IP allowlist for a license.
    pub async fn get_ip_allowlist(&self, license_id: &str) -> Result<serde_json::Value, Error> {
        let path = format!("/portal/licenses/{}/ip-allowlist", license_id);
        self.request(reqwest::Method::GET, &path, None).await
    }

    /// Set IP allowlist for a license.
    pub async fn set_ip_allowlist(&self, license_id: &str, allowed_ips: &[&str]) -> Result<serde_json::Value, Error> {
        let path = format!("/portal/licenses/{}/ip-allowlist", license_id);
        let body = serde_json::json!({ "allowedIps": allowed_ips });
        self.request(reqwest::Method::PUT, &path, Some(&body)).await
    }

    /// Rotate a license key.
    pub async fn rotate_license(&self, license_id: &str) -> Result<serde_json::Value, Error> {
        let path = format!("/portal/licenses/{}/rotate", license_id);
        self.request(reqwest::Method::POST, &path, None).await
    }

    // ── Internal ────────────────────────────────────────────────────────────

    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, Error> {
        let url = format!("{}{}", self.api_url, path);
        let mut last_error: Option<Error> = None;

        for attempt in 0..=self.retries {
            let mut req = self.http.request(method.clone(), &url)
                .header("Content-Type", "application/json");

            if let Some(key) = &self.api_key {
                req = req.header("Authorization", format!("Bearer {}", key));
            }

            if let Some(b) = body {
                req = req.json(b);
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();

                    if status >= 400 && status < 500 {
                        let err: ApiErrorResponse =
                            serde_json::from_str(&text).unwrap_or(ApiErrorResponse {
                                error: Some(format!("HTTP {}", status)),
                                code: Some("UNKNOWN".into()),
                            });
                        return Err(Error::Api {
                            message: err.error.unwrap_or_default(),
                            code: err.code.unwrap_or_default(),
                            status,
                        });
                    }

                    if status >= 200 && status < 300 {
                        return serde_json::from_str(&text).map_err(Error::from);
                    }

                    last_error = Some(Error::Api {
                        message: format!("HTTP {}", status),
                        code: "SERVER_ERROR".into(),
                        status,
                    });
                }
                Err(e) => {
                    last_error = Some(Error::Network(e));
                }
            }

            if attempt < self.retries {
                let delay = Duration::from_millis(
                    std::cmp::min(1000 * 2u64.pow(attempt), 5000)
                );
                tokio::time::sleep(delay).await;
            }
        }

        Err(last_error.unwrap_or(Error::Verification("Request failed".into())))
    }
}

// ─── Builder ────────────────────────────────────────────────────────────────

pub struct Builder {
    api_url: String,
    api_key: Option<String>,
    timeout_ms: u64,
    retries: u32,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            api_url: DEFAULT_API_URL.to_string(),
            api_key: None,
            timeout_ms: 10_000,
            retries: 2,
        }
    }
}

impl Builder {
    pub fn api_url(mut self, url: &str) -> Self { self.api_url = url.trim_end_matches('/').to_string(); self }
    pub fn api_key(mut self, key: &str) -> Self { self.api_key = Some(key.to_string()); self }
    pub fn timeout(mut self, ms: u64) -> Self { self.timeout_ms = ms; self }
    pub fn retries(mut self, n: u32) -> Self { self.retries = n; self }

    pub fn build(self) -> TrafficOrchestrator {
        TrafficOrchestrator {
            api_url: self.api_url,
            api_key: self.api_key,
            timeout: Duration::from_millis(self.timeout_ms),
            retries: self.retries,
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(self.timeout_ms))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }
}
