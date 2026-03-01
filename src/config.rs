use std::time::Duration;

pub struct ScanConfig {
    pub lab_id: String,
    pub base_url: String,
    pub username: String,
    pub password: String,
    /// Also try carlos:montoya as fallback credentials
    pub try_carlos: bool,
    pub custom_headers: Vec<(String, String)>,
    pub custom_cookies: Vec<(String, String)>,
    pub proxy_url: Option<String>,
    pub timeout: Duration,
    pub verbose: bool,
    /// Whether to emit JSON instead of human-readable text (used in main.rs only).
    pub _json_output: bool,
    pub output_file: Option<String>,
}
