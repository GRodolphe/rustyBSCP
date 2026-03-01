# rustyBSCP

Rust rewrite of [WSAAR](https://github.com/Nishacid/WSAAR).

Runs 18 vulnerability checks across three phases, reconstructs exposed `.git` repositories, and sprays credentials from embedded wordlists.

> **For authorized use only.** Intended for PortSwigger Web Security Academy labs.

## Features

- **Concurrent scanning**: unauthenticated checks run in parallel via `tokio::join!`; authenticated checks follow after login
- **Git repository reconstruction**: when `/.git/` is exposed, downloads and reconstructs the full repo into `/tmp/rbscp-git-<labid>/`
- **Credential spray**: username enumeration + password spray using embedded BSCP wordlists
- **Proxy support**: `--burp` for one-flag Burp Suite integration; `--proxy` for any HTTP proxy
- **Custom headers and cookies**: inject session tokens or auth headers without modifying source
- **JSON output**: machine-readable findings for piping or saving
- **18 check modules**: covers the full BSCP vulnerability surface

## Checks

| Phase | Module | What it detects |
| ------- | -------- | ----------------- |
| 1 (Unauthenticated) | `enumeration` | Admin panels, robots.txt, registration/search/comments/WebSocket endpoints, non-session cookies |
| 1 | `information_disclosure` | `.git` exposure, TRACE method, phpinfo, verbose errors, source maps |
| 1 | `cors` | Stock subdomain reflection, null/evil.com origin, ACAC misconfiguration |
| 1 | `web_cache` | X-Cache/Vary headers, cacheable tracking scripts, unkeyed header reflection |
| 1 | `ssrf` | `/product/stock` stockApi POST, `stockCheck.js` presence |
| 1 | `sqli` (pre-auth) | `/filter?category=` error-based and boolean-based, XML stockCheck |
| 1b (Git Dump) | `git_dump` | Directory crawl, object BFS, pack index, `git checkout` reconstruction |
| 2 (Auth) | `login` | CSRF extraction, session login, JWT detection, API key extraction, username enumeration |
| 3 (Authenticated) | `access_control` | `viewTranscript.js`, role param mass assignment, IDOR via `id` param |
| 3 | `oauth` | OAuth paths, `.well-known` endpoints, social login link extraction, `redirect_uri` manipulation |
| 3 | `lfi` | `/image?filename=` path traversal, other filename params |
| 3 | `upload` | File upload form detection, upload API endpoints |
| 3 | `sqli` (post-auth) | Search parameter injection |
| 3 | `xss` | 404 reflection, search reflection, jQuery/Angular version, `postMessage`, DOM sinks |
| 3 | `request_smuggling` | UA reflection, `/analytics` script, CL+TE conflicting headers |
| 3 | `websocket` | `ws://` in source, `/chat` WS upgrade |
| 3 | `prototype_pollution` | `Object.assign`/`_.merge` gadgets, server-side `__proto__` injection |
| 3 | `deserialization` | PHP serialized cookies, Java `0xACED` magic bytes, .NET ViewState |
| 3 | `business_logic` | Cart endpoint, coupon `/cart/coupon`, negative quantity |

## Install

```sh
git clone https://github.com/youruser/rustyBSCP
cd rustyBSCP
cargo build --release
# Binary at target/release/rbscp
```

Requires Rust stable (install via [rustup](https://rustup.rs)).

## Usage

```text
rbscp -i <LAB_ID> [OPTIONS]
```

The lab ID is the 32-character hex string from your lab URL:

```text
https://0a1b2c3d4e5f...0000.web-security-academy.net/
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

### Options

```text
  -i, --id <ID>            Lab ID (32-char hex)
  -u, --username <USER>    Username [default: wiener]
  -p, --password <PASS>    Password [default: peter]
      --try-carlos         Also try carlos:montoya as fallback credentials
  -b, --burp               Route through Burp Suite (127.0.0.1:8080)
      --proxy <URL>        Custom proxy URL (overrides --burp)
  -H, --header <HEADER>    Custom request header "Name: Value" (repeatable)
  -C, --cookie <COOKIE>    Custom cookie "name=value" (repeatable)
      --timeout <SECS>     Request timeout in seconds [default: 15]
      --json               Output findings as JSON
  -v, --verbose            Show verbose output
      --no-color           Disable ANSI colour
  -o, --output <FILE>      Save JSON findings to file
```

### Examples

```sh
# Basic scan
rbscp -i 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d

# Route through Burp, custom credentials
rbscp -i 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d --burp -u administrator -p secret

# Inject a session cookie, save findings
rbscp -i 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d \
  -C "session=abc123" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -o findings.json

# JSON output for scripting
rbscp -i 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d --json | jq '.[] | select(.severity == "High")'
```

## Git Dump

When `/.git/HEAD` is reachable, `git_dump` automatically:

1. Crawls directory listings (if enabled on the server)
2. Downloads 28 known git metadata paths
3. BFS-traverses the object graph (commits, trees, blobs)
4. Parses pack index files (v1 and v2) to recover packed objects
5. Sanitizes `.git/config` (comments out `fsmonitor`, `sshCommand`, etc.)
6. Runs `git checkout HEAD -- .` to reconstruct the working tree

The reconstructed repository lands at `/tmp/rbscp-git-<labid>/`.

```sh
git -C /tmp/rbscp-git-<labid> log --oneline --all
git -C /tmp/rbscp-git-<labid> diff HEAD~1
```

## Wordlists

Credential wordlists are embedded at compile time from the [botesjuan BSCP study repo](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study/tree/main/wordlists). No runtime file dependencies.

## Credits

- [WSAAR](https://github.com/Nishacid/WSAAR) by Nishacid, the original Python recon tool this was based on
- [git-dumper](https://github.com/arthaud/git-dumper) by arthaud, git reconstruction algorithm
- [BSCP Study Guide wordlists](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study) by botesjuan
