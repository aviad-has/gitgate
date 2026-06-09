# GitGate

**A self-hosted, policy-enforcing proxy for `git clone`.**

Every time a developer runs `git clone https://github.com/...`, arbitrary code enters your network. Until recently that was an acceptable tradeoff. The agent era changed the math: GitHub now sees millions of new repositories per month, most of them AI-generated, most of them unreviewed. Your developers are one `git clone` away from running any of them.

GitGate sits between your developers and GitHub. Allowed repos clone normally. Everything else is blocked before a single byte of code crosses the boundary — with a reason logged.

```
$ git clone https://github.com/sketchy/brand-new-package
remote: GitGate: clone blocked
remote: Reason: repo_too_young (3 days old, minimum 30)
remote: Contact your security team to request an exception.
fatal: repository not found
```

---

## Quick start

**Prerequisites:** Docker, Docker Compose.

```sh
git clone https://github.com/your-org/gitgate
cd gitgate
cp policy.yaml.example policy.yaml   # edit to taste
docker compose up -d
```

First run generates a private CA and server certificate in `./certs/`.

**Install the CA on developer machines** (once per machine, run as admin):

```sh
# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ./certs/ca.crt

# Linux (Debian/Ubuntu)
sudo cp ./certs/ca.crt /usr/local/share/ca-certificates/gitgate.crt
sudo update-ca-certificates

# Windows
certutil -addstore -f "ROOT" certs\ca.crt
```

**Configure git on developer machines** (replace `proxy.yourdomain.com` with your proxy's address):

```sh
git config --global \
  url."https://proxy.yourdomain.com:7443/".insteadOf "https://github.com/"
```

Done. Every `git clone https://github.com/...` now goes through GitGate. Developers notice nothing for allowed repos.

---

## Policy

Edit `policy.yaml` to match your org's requirements:

```yaml
# Only allow OSI-approved permissive licenses
license_allowlist:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC

# Block repos with no license at all
no_license_action: block

# Ignore repos younger than 30 days
min_repo_age_days: 30

# Always block these orgs/users
org_blocklist: []

# Specific repos that bypass all checks (your own internal mirrors, etc.)
exceptions:
  - my-org/approved-internal-tool
```

Full reference with all options: [`policy.yaml.example`](policy.yaml.example).

---

## What developers see

**Allowed:**
```
$ git clone https://github.com/torvalds/linux
  GitGate: ALLOW — license: GPL-2.0
Cloning into 'linux'...
remote: Enumerating objects: ...
```

**Blocked:**
```
$ git clone https://github.com/sketchy/new-package
remote: GitGate: clone blocked
remote: Reason: no_license
remote:
remote: Contact your security team to request an exception.
fatal: repository 'https://github.com/sketchy/new-package/' not found
```

The blocking message appears verbatim in the developer's terminal. No guessing why — they know exactly which policy rule triggered and who to ask.

---

## Already blocked GitHub?

If your security team blocked `github.com` at the firewall after an incident, GitGate is the path back.

Deploy GitGate inside your network. Update the firewall to allow outbound HTTPS from the GitGate host to `github.com` and `api.github.com`. Developers configure the git redirect above. GitHub access is restored — gated by your policy.

---

## How it works

GitGate is a git smart-HTTP proxy. It speaks the same protocol GitHub does.

1. Developer runs `git clone https://github.com/owner/repo`
2. git contacts the proxy instead (via the `url.insteadOf` config)
3. GitGate calls the GitHub API to fetch repo metadata (license, age, stars, owner)
4. Policy engine evaluates the request → **ALLOW** or **BLOCK**
5. ALLOW: GitGate forwards the request to GitHub and streams the pack data back
6. BLOCK: GitGate returns HTTP 403 with the reason; git prints it as `remote: ...`
7. Every decision is written to the audit log

The code for an allowed repo transfers directly from GitHub to the developer — GitGate is not in the data path beyond the initial handshake. Large repos and monorepos are not buffered.

---

## Custom hostname and port

By default the proxy runs on port `7443` with `localhost` in the certificate SAN. For a production deployment, set the hostname before first run:

```sh
GITGATE_HOSTNAME=proxy.yourdomain.com docker compose up -d
```

Or generate certificates manually:
```sh
gitgate-cert generate --out-dir ./certs --hostname proxy.yourdomain.com
```

---

## Configuration reference

| Environment variable | Default | Description |
|---|---|---|
| `GITGATE_HOSTNAME` | `localhost` | Hostname in the generated TLS certificate |
| `GITGATE_PORT` | `7443` | Port the proxy listens on |
| `GITGATE_GITHUB_TOKEN` | _(none)_ | GitHub token for higher API rate limits |

---

## Status

- [x] Policy engine — license, age, stars, org allowlist/blocklist, per-repo exceptions
- [x] HTTPS proxy with auto-generated self-signed CA
- [x] Audit log (JSON, one entry per decision)
- [x] Docker Compose install
- [ ] Web UI for audit log and exception requests
- [ ] Redirect mode (for orgs where devs can still reach GitHub directly)

---

## Building from source

Requires Rust 1.75+.

```sh
cargo build --release
```

Produces three binaries in `target/release/`: `gitgate-proxy`, `gitgate-cert`, and `gitgate`.

**`gitgate` — CLI for individual use, no proxy required:**

```sh
gitgate check owner/repo      # dry-run policy check, no clone
gitgate clone owner/repo      # policy check then git clone
gitgate policy show           # show active policy and where it loaded from
```

Useful for testing a policy file before deploying, or for individual developers who want policy enforcement without org-wide proxy infrastructure.

---

## Why self-hosted?

Your clone traffic contains the names of every repository your organization depends on. Routing that through a third-party service is a different kind of risk. GitGate is installed by your IT team, runs in your network, and the code is open for your security team to read.

---

## License

MIT
