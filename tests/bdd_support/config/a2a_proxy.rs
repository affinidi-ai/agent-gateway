use std::path::Path;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct A2aProxyFixture {
    pub proxy_id: String,
    pub name: String,
    pub secret_id: String,
    pub base_url: String,
    pub disabled: bool,
    pub timeout_secs: u32,
    pub poll_interval_ms: u32,
    pub max_poll_attempts: u32,
}

impl A2aProxyFixture {
    pub fn new(
        proxy_id: impl Into<String>,
        name: impl Into<String>,
        secret_id: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            name: name.into(),
            secret_id: secret_id.into(),
            base_url: base_url.into(),
            disabled: false,
            timeout_secs: 5,
            poll_interval_ms: 100,
            max_poll_attempts: 3,
        }
    }

    pub fn with_disabled(mut self) -> Self {
        self.disabled = true;
        self
    }

    pub fn with_fast_timeout(mut self) -> Self {
        self.timeout_secs = 1;
        self.poll_interval_ms = 100;
        self.max_poll_attempts = 3;
        self
    }
}

pub fn write_a2a_proxy_fixture(
    dir: &Path,
    fixture: &A2aProxyFixture,
) {
    std::fs::create_dir_all(dir).unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    let record = serde_json::json!({
        "id": fixture.proxy_id,
        "name": fixture.name,
        "description": format!("BDD A2A proxy {}", fixture.proxy_id),
        "status": if fixture.disabled { "disabled" } else { "active" },
        "backend": {
            "kind": "copilot_direct_line",
            "secret_id": fixture.secret_id,
            "credential_mode": "secret",
            "base_url": fixture.base_url,
            "timeout_secs": fixture.timeout_secs,
            "poll_interval_ms": fixture.poll_interval_ms,
            "max_poll_attempts": fixture.max_poll_attempts
        },
        "agent_card": {
            "name": fixture.name,
            "description": format!("BDD A2A proxy {}", fixture.proxy_id)
        },
        "created_at": now,
        "updated_at": now,
    });
    std::fs::write(dir.join(format!("{}.json", fixture.proxy_id)), serde_json::to_string_pretty(&record).unwrap())
        .unwrap();
}
