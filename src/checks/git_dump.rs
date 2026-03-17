//! Git repository reconstruction from an exposed `/.git/` directory.
//!
//! Algorithm (mirrors git-dumper by arthaud):
//! 1. Probe `/.git/HEAD` — abort if not reachable.
//! 2. Try directory listing at `/.git/` and crawl recursively if available.
//! 3. Download a hardcoded set of well-known git metadata files.
//! 4. BFS over all SHA-1 hashes found in text files:
//!    - download each loose object from `/.git/objects/XX/YY…`
//!    - zlib-decompress it, parse the git header
//!    - extract child SHAs (commit → tree + parents; tree → entries)
//! 5. Download pack files (`.pack` + `.idx`) listed in `objects/info/packs`.
//!    Parse the pack-index v2 binary to extract every packed SHA.
//! 6. Sanitize the checked-out `config` (comment out dangerous hooks).
//! 7. Run `git checkout HEAD -- .` to reconstruct the working tree.

use std::{
    collections::{HashSet, VecDeque},
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use regex::Regex;
use tokio::fs;

use crate::{
    output::{Finding, Severity},
    scanner::ScanContext,
};

// ── Well-known git metadata paths ────────────────────────────────────────────

const INITIAL_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.git/description",
    "/.git/COMMIT_EDITMSG",
    "/.git/ORIG_HEAD",
    "/.git/FETCH_HEAD",
    "/.git/MERGE_HEAD",
    "/.git/index",
    "/.git/info/exclude",
    "/.git/info/refs",
    "/.git/objects/info/packs",
    "/.git/packed-refs",
    "/.git/refs/stash",
    "/.git/refs/heads/master",
    "/.git/refs/heads/main",
    "/.git/refs/heads/develop",
    "/.git/refs/heads/development",
    "/.git/refs/heads/staging",
    "/.git/refs/heads/production",
    "/.git/refs/remotes/origin/HEAD",
    "/.git/refs/remotes/origin/master",
    "/.git/refs/remotes/origin/main",
    "/.git/logs/HEAD",
    "/.git/logs/refs/heads/master",
    "/.git/logs/refs/heads/main",
    "/.gitignore",
    "/.git/hooks/pre-commit.sample",
    "/.git/hooks/pre-push.sample",
];

// ── Public entry point ────────────────────────────────────────────────────────

pub async fn run(ctx: &Arc<ScanContext>) -> Vec<Finding> {
    // Quick probe — don't attempt dump if HEAD is not readable
    if !probe_git_head(ctx).await {
        return Vec::new();
    }

    let output_dir = std::env::temp_dir().join(format!("rbscp-git-{}", ctx.config.lab_id));

    ctx.out.info(&format!(
        "Exposed .git found — dumping repo to {}",
        output_dir.display()
    ));

    match dump(ctx, &output_dir).await {
        Ok(stats) => {
            let msg = format!(
                "Git repo reconstructed at {} ({} objects, {} files)",
                output_dir.display(),
                stats.objects,
                stats.files,
            );
            let detail = format!(
                "Inspect: git -C {} log --oneline --all",
                output_dir.display()
            );
            let f = Finding::new(Severity::High, "Git Dump", msg).with_details(detail);
            ctx.out.finding(&f);
            ctx.out.success(&format!(
                "git -C {} log --oneline --all",
                output_dir.display()
            ));
            vec![f]
        }
        Err(e) => {
            ctx.out.warn(&format!("Git dump incomplete: {e:#}"));
            Vec::new()
        }
    }
}

// ── Internal stats ────────────────────────────────────────────────────────────

struct Stats {
    objects: usize,
    files: usize,
}

// ── Core dump logic ───────────────────────────────────────────────────────────

async fn dump(ctx: &Arc<ScanContext>, out: &Path) -> Result<Stats> {
    // Create skeleton
    fs::create_dir_all(out.join(".git/objects")).await?;
    fs::create_dir_all(out.join(".git/refs")).await?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut files = 0usize;
    let mut objects = 0usize;

    let sha_re =
        Regex::new(r"(?:^|[^0-9a-f])([0-9a-f]{40})(?:[^0-9a-f]|$)").context("SHA regex")?;
    let ref_re = Regex::new(r"refs/[a-zA-Z0-9/._-]+").context("ref regex")?;
    let pack_re = Regex::new(r"pack-([0-9a-f]{40})\.pack").context("pack regex")?;

    // ── 1. Directory listing crawl (opportunistic) ────────────────────────
    if has_directory_listing(ctx).await {
        ctx.out
            .info("Directory listing available — crawling /.git/");
        files += Box::pin(crawl(ctx, "/.git/", out)).await.unwrap_or(0);
    }

    // ── 2. Well-known initial files ───────────────────────────────────────
    for &path in INITIAL_PATHS {
        if fetch_and_save(ctx, path, out).await.is_ok() {
            files += 1;
        }
    }

    // ── 3. Harvest SHAs from text files ──────────────────────────────────
    harvest_text_shas(out, &sha_re, &ref_re, &mut seen, &mut queue);

    // Download any ref files referenced in text
    let extra_refs: Vec<String> = {
        let git_dir = out.join(".git");
        let mut refs = Vec::new();
        collect_text_refs(&git_dir, &ref_re, &mut refs);
        refs
    };
    for r in &extra_refs {
        let web_path = format!("/.git/{r}");
        if fetch_and_save(ctx, &web_path, out).await.is_ok() {
            files += 1;
            // Re-harvest after new file
            harvest_text_shas(out, &sha_re, &ref_re, &mut seen, &mut queue);
        }
    }

    // ── 4. BFS over loose objects ─────────────────────────────────────────
    while let Some(sha) = queue.pop_front() {
        if sha.len() != 40 {
            continue;
        }
        let (prefix, suffix) = sha.split_at(2);
        let web_path = format!("/.git/objects/{prefix}/{suffix}");
        let local_path = out.join(format!(".git/objects/{prefix}/{suffix}"));

        if local_path.exists() {
            continue;
        }

        let Ok(bytes) = fetch_raw(ctx, &web_path).await else {
            // Object may be in a pack — not an error
            continue;
        };

        if let Some(parent) = local_path.parent() {
            let _ = fs::create_dir_all(parent).await;
        }
        let _ = fs::write(&local_path, &bytes).await;
        objects += 1;

        // Parse object to find referenced SHAs
        if let Ok(decompressed) = zlib_decompress(&bytes) {
            for child_sha in parse_object_refs(&decompressed) {
                if seen.insert(child_sha.clone()) {
                    queue.push_back(child_sha);
                }
            }
        }
    }

    // ── 5. Pack files ─────────────────────────────────────────────────────
    let packs_file = out.join(".git/objects/info/packs");
    if let Ok(content) = fs::read_to_string(&packs_file).await {
        for cap in pack_re.captures_iter(&content) {
            let pack_sha = cap.get(1).map_or("", |m| m.as_str());
            let idx_path = format!("/.git/objects/pack/pack-{pack_sha}.idx");
            let pack_path = format!("/.git/objects/pack/pack-{pack_sha}.pack");

            let _ = fetch_and_save(ctx, &idx_path, out).await;
            let _ = fetch_and_save(ctx, &pack_path, out).await;
            files += 2;

            // Extract SHAs from the pack index so we know what's available
            let local_idx = out.join(format!(".git/objects/pack/pack-{pack_sha}.idx"));
            if let Ok(idx_bytes) = fs::read(&local_idx).await {
                for sha in parse_pack_index(&idx_bytes) {
                    seen.insert(sha); // register but don't queue (already in pack)
                }
            }
        }
    }

    // ── 6. Sanitize config ────────────────────────────────────────────────
    sanitize_config(out).await;

    // ── 7. Checkout ───────────────────────────────────────────────────────
    checkout(ctx, out).await;

    Ok(Stats { objects, files })
}

// ── Git probe ─────────────────────────────────────────────────────────────────

async fn probe_git_head(ctx: &Arc<ScanContext>) -> bool {
    let Ok(r) = ctx.client.get(ctx.url("/.git/HEAD")).send().await else {
        return false;
    };
    if !r.status().is_success() {
        return false;
    }
    let body = r.text().await.unwrap_or_default();
    body.starts_with("ref:") || body.trim().len() == 40
}

async fn has_directory_listing(ctx: &Arc<ScanContext>) -> bool {
    let Ok(r) = ctx.client.get(ctx.url("/.git/")).send().await else {
        return false;
    };
    if !r.status().is_success() {
        return false;
    }
    let body = r.text().await.unwrap_or_default();
    body.contains("Index of") || (body.contains("HEAD") && body.contains("href"))
}

// ── Directory crawl ───────────────────────────────────────────────────────────

async fn crawl(ctx: &Arc<ScanContext>, path: &str, out: &Path) -> Result<usize> {
    let Ok(r) = ctx.client.get(ctx.url(path)).send().await else {
        return Ok(0);
    };
    let body = r.text().await.unwrap_or_default();
    let link_re = Regex::new(r#"href="([^"/?#][^"]*?)""#)?;

    let mut count = 0;
    let depth = path.chars().filter(|&c| c == '/').count();

    for cap in link_re.captures_iter(&body) {
        let link = cap.get(1).map_or("", |m| m.as_str());
        if link.starts_with("..") {
            continue;
        }
        let full = format!("{path}{link}");
        if link.ends_with('/') {
            if depth < 8 {
                count += Box::pin(crawl(ctx, &full, out)).await.unwrap_or(0);
            }
        } else if fetch_and_save(ctx, &full, out).await.is_ok() {
            count += 1;
        }
    }
    Ok(count)
}

// ── File fetch helpers ────────────────────────────────────────────────────────

async fn fetch_and_save(ctx: &Arc<ScanContext>, web_path: &str, out: &Path) -> Result<()> {
    let bytes = fetch_raw(ctx, web_path).await?;
    // Map web path to local path: strip leading '/'
    let rel = web_path.trim_start_matches('/');
    let local = out.join(rel);
    if let Some(parent) = local.parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(local, bytes).await?;
    Ok(())
}

async fn fetch_raw(ctx: &Arc<ScanContext>, web_path: &str) -> Result<Vec<u8>> {
    let resp = ctx
        .client
        .get(ctx.url(web_path))
        .send()
        .await
        .with_context(|| format!("GET {web_path}"))?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("HTTP {} for {web_path}", resp.status()));
    }
    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}

// ── SHA harvesting ────────────────────────────────────────────────────────────

/// Walk all non-binary files under `.git/` and extract SHAs + refs into the queue.
fn harvest_text_shas(
    out: &Path,
    sha_re: &Regex,
    ref_re: &Regex,
    seen: &mut HashSet<String>,
    queue: &mut VecDeque<String>,
) {
    let git_dir = out.join(".git");
    let mut text_files: Vec<PathBuf> = Vec::new();
    collect_text_files(&git_dir, &mut text_files);

    for path in text_files {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };

        for cap in sha_re.captures_iter(text) {
            let sha = cap.get(1).map_or("", |m| m.as_str()).to_string();
            if sha.len() == 40 && seen.insert(sha.clone()) {
                queue.push_back(sha);
            }
        }
        // Collect ref paths for later fetch
        let _ = ref_re; // used in collect_text_refs
    }
}

fn collect_text_refs(git_dir: &Path, ref_re: &Regex, refs: &mut Vec<String>) {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_text_files(git_dir, &mut files);
    for path in files {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        for m in ref_re.find_iter(text) {
            refs.push(m.as_str().to_string());
        }
    }
}

/// Recursively collect non-binary files under a directory, skipping `objects/`.
fn collect_text_files(dir: &Path, acc: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // Skip the raw object store and pack directory — binary only
            if name != "objects" && name != "pack" {
                collect_text_files(&p, acc);
            }
        } else {
            acc.push(p);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert a raw byte slice to a lowercase hex string.
fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// ── Git object parsing ────────────────────────────────────────────────────────

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// Returns child SHA-1 references found in a decompressed git object.
fn parse_object_refs(decompressed: &[u8]) -> Vec<String> {
    // Header ends at the first null byte: "<type> <size>\0<data>"
    let Some(null_pos) = decompressed.iter().position(|&b| b == 0) else {
        return Vec::new();
    };
    let header = std::str::from_utf8(&decompressed[..null_pos]).unwrap_or("");
    let data = &decompressed[null_pos + 1..];

    let kind = header.split(' ').next().unwrap_or("");
    match kind {
        "commit" => parse_commit(data),
        "tree" => parse_tree(data),
        "tag" => parse_tag(data),
        _ => Vec::new(), // blob: leaf node, no refs
    }
}

fn parse_commit(data: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(data).unwrap_or("");
    let mut shas = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            break; // blank line separates headers from message
        }
        let mut parts = line.splitn(2, ' ');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("").trim();
        if (key == "tree" || key == "parent") && val.len() == 40 {
            shas.push(val.to_string());
        }
    }
    shas
}

/// Tree objects are binary: `<mode> <name>\0<20-byte raw SHA>` repeated.
fn parse_tree(data: &[u8]) -> Vec<String> {
    let mut shas = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        // Find null terminator after "<mode> <name>"
        let Some(rel) = data[pos..].iter().position(|&b| b == 0) else {
            break;
        };
        let sha_start = pos + rel + 1;
        let sha_end = sha_start + 20;
        if sha_end > data.len() {
            break;
        }
        let raw_sha = &data[sha_start..sha_end];
        shas.push(bytes_to_hex(raw_sha));
        pos = sha_end;
    }
    shas
}

fn parse_tag(data: &[u8]) -> Vec<String> {
    let text = std::str::from_utf8(data).unwrap_or("");
    text.lines()
        .filter_map(|line| {
            let mut p = line.splitn(2, ' ');
            let key = p.next()?;
            let val = p.next()?.trim();
            (key == "object" && val.len() == 40).then(|| val.to_string())
        })
        .collect()
}

// ── Pack index v2 parser ──────────────────────────────────────────────────────

/// Parse a pack index file (v1 or v2) and return all SHA-1 hashes it contains.
fn parse_pack_index(data: &[u8]) -> Vec<String> {
    if data.len() < 8 {
        return Vec::new();
    }
    // v2 magic: \xff\x74\x4f\x63
    let is_v2 = data[0] == 0xff && data[1] == 0x74 && data[2] == 0x4f && data[3] == 0x63;

    if is_v2 {
        parse_pack_index_v2(data)
    } else {
        parse_pack_index_v1(data)
    }
}

fn parse_pack_index_v2(data: &[u8]) -> Vec<String> {
    // Header: 4 magic + 4 version + 256*4 fan-out table
    let fan_out_end = 8 + 256 * 4;
    if data.len() < fan_out_end + 4 {
        return Vec::new();
    }
    // Last fan-out entry = total object count
    let n_offset = fan_out_end - 4;
    let n = u32::from_be_bytes([
        data[n_offset],
        data[n_offset + 1],
        data[n_offset + 2],
        data[n_offset + 3],
    ]) as usize;

    let sha_start = fan_out_end;
    let sha_end = sha_start + n * 20;
    if data.len() < sha_end {
        return Vec::new();
    }

    (0..n)
        .map(|i| bytes_to_hex(&data[sha_start + i * 20..sha_start + i * 20 + 20]))
        .collect()
}

fn parse_pack_index_v1(data: &[u8]) -> Vec<String> {
    // v1: 256*4 fan-out table, then N * (4 offset + 20 SHA)
    let fan_out_end = 256 * 4;
    if data.len() < fan_out_end + 4 {
        return Vec::new();
    }
    let n_offset = fan_out_end - 4;
    let n = u32::from_be_bytes([
        data[n_offset],
        data[n_offset + 1],
        data[n_offset + 2],
        data[n_offset + 3],
    ]) as usize;

    let entries_start = fan_out_end;
    (0..n)
        .filter_map(|i| {
            let offset = entries_start + i * 24 + 4; // skip 4-byte offset field
            let end = offset + 20;
            if end > data.len() {
                return None;
            }
            Some(bytes_to_hex(&data[offset..end]))
        })
        .collect()
}

// ── Config sanitizer ──────────────────────────────────────────────────────────

/// Comment out dangerous git config options before running `git checkout`.
async fn sanitize_config(out: &Path) {
    let config_path = out.join(".git/config");
    let Ok(content) = fs::read_to_string(&config_path).await else {
        return;
    };

    let dangerous = [
        "fsmonitor",
        "sshcommand",
        "askpass",
        "editor",
        "pager",
        "gpgsign",
        "signingkey",
    ];
    let mut sanitized = String::with_capacity(content.len() + 64);
    for line in content.lines() {
        let lower = line.to_ascii_lowercase();
        if dangerous.iter().any(|d| lower.contains(d)) {
            sanitized.push_str("# [sanitized by rbscp] ");
        }
        sanitized.push_str(line);
        sanitized.push('\n');
    }
    let _ = fs::write(&config_path, sanitized).await;
}

// ── Repo checkout ─────────────────────────────────────────────────────────────

async fn checkout(ctx: &Arc<ScanContext>, out: &Path) {
    // Check git is available
    if tokio::process::Command::new("git")
        .arg("--version")
        .output()
        .await
        .is_err()
    {
        ctx.out
            .warn("git not found — skipping checkout. Run manually:");
        ctx.out
            .info(&format!("  git -C {} checkout .", out.display()));
        return;
    }

    // Attempt `git checkout HEAD -- .`
    let result = tokio::process::Command::new("git")
        .current_dir(out)
        .args(["checkout", "HEAD", "--", "."])
        .output()
        .await;

    match result {
        Ok(o) if o.status.success() => {
            ctx.out
                .success("Working tree reconstructed via git checkout");
        }
        Ok(o) => {
            if ctx.config.verbose {
                ctx.out.verbose(&format!(
                    "git checkout HEAD failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                ));
            }
            // Fallback: bare checkout (uses whatever HEAD resolves to)
            let r2 = tokio::process::Command::new("git")
                .current_dir(out)
                .args(["checkout", "."])
                .output()
                .await;
            if r2.is_ok_and(|o| o.status.success()) {
                ctx.out
                    .success("Working tree reconstructed via git checkout .");
            } else {
                ctx.out
                    .warn("Objects downloaded but checkout incomplete — try:");
                ctx.out
                    .info(&format!("  git -C {} log --all --oneline", out.display()));
            }
        }
        Err(e) => ctx.out.warn(&format!("git checkout failed: {e}")),
    }
}
