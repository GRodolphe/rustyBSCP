pub mod access_control;
pub mod business_logic;
pub mod cors;
pub mod crawl;
pub mod deserialization;
pub mod enumeration;
pub mod git_dump;
pub mod information_disclosure;
pub mod lfi;
pub mod login;
pub mod oauth;
pub mod prototype_pollution;
pub mod request_smuggling;
pub mod sqli;
pub mod ssrf;
pub mod upload;
pub mod web_cache;
pub mod websocket;
pub mod xss;

/// Username wordlist embedded at compile time.
pub const USERNAMES: &str = include_str!("../../wordlists/usernames.txt");

/// Password wordlist embedded at compile time.
pub const PASSWORDS: &str = include_str!("../../wordlists/passwords.txt");

/// Iterate non-empty, trimmed lines from an embedded wordlist.
pub fn wordlist_lines(wl: &str) -> impl Iterator<Item = &str> {
    wl.lines().map(str::trim).filter(|l| !l.is_empty())
}

