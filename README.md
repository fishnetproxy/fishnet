# 🐟 Fishnet

**The only door between your AI agent and the real world.**

Local-first security proxy for AI agents. Single Rust binary. Open source. Nothing leaves your machine.

---

AI agents hold your API keys, make payments, execute trades, and talk to the internet on your behalf — with zero guardrails. Fishnet sits between your agent and the outside world, enforcing the rules you set.

Your agent never touches real credentials. Every request flows through Fishnet. Every decision is logged.

## What It Does

- **Credential Isolation** — Your API keys live in an encrypted vault. The agent gets a localhost proxy. It never sees the real keys.
- **Spend Caps & Rate Limits** — Set a daily budget. When it's hit, the door closes. No more $300 surprises from a runaway loop.
- **Endpoint Blocking** — Withdrawals from your exchange account? Blocked at the proxy layer. Physically impossible through Fishnet.
- **Onchain Permits** — Agent wants to swap on Uniswap? Fishnet checks the contract, the function, the amount — then signs a cryptographic permit. No permit, no execution.
- **Tamper-Proof Audit Trail** — Every approved and denied action is logged in a Merkle tree. Optionally generate ZK proofs that attest to compliance without revealing what your agent did.

## Who It's For

Anyone running an AI agent with access to paid APIs or real money. If your agent has an OpenAI key, a Binance key, or a funded wallet — you need this.

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (1.85+)
- [Node.js](https://nodejs.org/) (22+)
- [Docker](https://www.docker.com/) (optional, for containerised deployment)

### Install Dependencies

```sh
make install      # install frontend (dashboard) npm packages
```

### Development

```sh
make dev          # start API + Vite dev server in parallel
                  # API  → http://localhost:8473
                  # App  → http://localhost:5173 (proxies /api → :8473)

make dev-api      # backend only
make dev-fe       # frontend only (assumes API already running)
make dev-watch    # backend with auto-reload (needs: cargo install cargo-watch)
```

### Production

#### Single binary (recommended)

Builds the React dashboard into the Rust binary — one file, no external assets.

```sh
make build-prod   # builds frontend, then compiles with --features embed-dashboard
./target/release/fishnet
```

#### Release install script (Linux/macOS)

```sh
curl -fsSL https://github.com/iamyxsh/fishnet/releases/latest/download/install.sh | sh
```

Install path defaults to `~/.local/bin` (override with `INSTALL_DIR=/your/path`).
Runtime data defaults to `/var/lib/fishnet` (Linux) or `/Library/Application Support/Fishnet` (macOS).
For local dev/CI, override with `FISHNET_DATA_DIR=/your/path`.

#### Docker

```sh
make docker-up    # build image & start container (http://localhost:8473)
make docker-logs  # tail logs
make docker-down  # stop
make docker-clean # remove container, volume, and image
```

For tagged releases, multi-arch Docker images are published to:

```sh
docker pull d3vdhruv/fishnet:<version>
docker pull d3vdhruv/fishnet:latest
```

#### Homebrew (release automation)

Homebrew formula generation is automated on release publish. Optional tap publishing can be enabled via repo settings:

- Repo variable: `HOMEBREW_TAP_REPOSITORY` (for example `d3vdhruv/homebrew-tap`)
- Repo secret: `HOMEBREW_TAP_TOKEN`

### Quality

```sh
make test         # run Rust tests
make fmt          # format code
make check        # clippy lints
make clean        # remove all build artifacts
```

## Status

🚧 **Pre-release** — Actively building. Star the repo to follow along.

## Links

- 📖 Docs (coming soon)
- 🐦 [@FishnetDev](https://twitter.com/FishnetDev)
- 💬 Discord (coming soon)

---

*Built with Rust. Runs locally. Trusts no one.*
