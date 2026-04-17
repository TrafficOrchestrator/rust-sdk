# traffic-orchestrator-rust

Official Rust SDK for [Traffic Orchestrator](https://trafficorchestrator.com) — async license validation with `tokio`.

📖 [API Reference](https://trafficorchestrator.com/docs#api) · [SDK Guides](https://trafficorchestrator.com/docs/sdk/rust) · [OpenAPI Spec](https://api.trafficorchestrator.com/api/v1/openapi.json)

## Install

```toml
[dependencies]
traffic-orchestrator = "2.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use traffic_orchestrator::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let result = client.validate_license("LK-xxxx", Some("example.com")).await?;

    if result.valid {
        println!("Plan: {}", result.plan_id.unwrap_or_default());
    }
    Ok(())
}
```

## API Methods

### Core License Operations

| Method | Auth | Description |
| --- | --- | --- |
| `validate_license(token, domain)` | No | Validate a license key |
| `verify_offline(token, public_key, domain)` | No | Ed25519 offline verification |
| `list_licenses()` | Yes | List all licenses |
| `create_license(opts)` | Yes | Create a new license |
| `rotate_license(license_id)` | Yes | Rotate license key |
| `delete_license(license_id)` | Yes | Revoke a license |
| `get_usage()` | Yes | Get usage statistics |
| `get_analytics(days)` | Yes | Get detailed analytics |
| `health_check()` | No | Check API health |

### Portal & Enterprise Methods

| Method | Auth | Description |
| --- | --- | --- |
| `add_domain(license_id, domain)` | Yes | Add domain to license |
| `remove_domain(license_id, domain)` | Yes | Remove domain from license |
| `get_domains(license_id)` | Yes | Get license domains |
| `update_license_status(id, status)` | Yes | Suspend/reactivate license |
| `list_api_keys()` | Yes | List API keys |
| `create_api_key(name, scopes)` | Yes | Create API key |
| `delete_api_key(key_id)` | Yes | Delete API key |
| `get_dashboard()` | Yes | Full dashboard overview |

## Error Handling

```rust
use traffic_orchestrator::{Client, Error};

match client.validate_license(token, domain).await {
    Ok(result) => println!("Valid: {}", result.valid),
    Err(Error::Api { code, message, status }) => {
        eprintln!("API error {status}: {code} — {message}");
    }
    Err(Error::Network(e)) => eprintln!("Network: {e}"),
    Err(Error::Timeout) => eprintln!("Timed out"),
}
```

## Multi-Environment

```rust
// Production (default)
let client = Client::builder()
    .api_key(std::env::var("TO_API_KEY")?)
    .build();

// Staging
let client = Client::builder()
    .api_key(std::env::var("TO_API_KEY_DEV")?)
    .base_url("https://api-staging.trafficorchestrator.com/api/v1")
    .build();
```

## Async Runtime

Built on `tokio` with `reqwest` for HTTP. All methods are `async fn` and return `Result<T, Error>`.

## Offline Verification (Enterprise)

Validate licenses locally without API calls using Ed25519 JWT signatures:

```rust
use traffic_orchestrator::Client;

let client = Client::builder()
    .public_key(std::env::var("TO_PUBLIC_KEY")?)
    .build();

let result = client.verify_offline(license_token).await?;
if result.valid {
    println!("Plan: {}", result.plan_id.unwrap_or_default());
}
```

## Requirements

- Rust 1.70+ (edition 2021)
- `tokio` 1.x, `reqwest` 0.11+

## License

MIT
