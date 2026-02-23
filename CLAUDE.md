# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Wardgate is an AI agent security gateway written in Go 1.24. It sits between AI agents and external services to provide credential isolation, access control, audit logging, approval workflows, and rate limiting. Agents never see real credentials — Wardgate injects them at proxy time.

Module: `github.com/wardgate/wardgate`

## Commands

```bash
# Build all binaries
go build -v ./...

# Run all tests (CI uses this exact command)
go test -v -race ./...

# Run tests for a single package
go test -v -race ./internal/policy

# Run a single test
go test -v -race -run TestEvaluate_AllowGET ./internal/policy

# Build individual binaries
go build -o wardgate ./cmd/wardgate
go build -o wardgate-cli ./cmd/wardgate-cli
go build -o wardgate-exec ./cmd/wardgate-exec

# Build wardgate-cli with fixed config path (cannot be overridden by agents)
go build -ldflags "-X main.configPath=/etc/wardgate-cli/config.yaml" -o wardgate-cli ./cmd/wardgate-cli
```

There is no separate lint or format step beyond `go vet` (run implicitly by `go test`).

## Architecture

### Three Binaries

- **wardgate** (`cmd/wardgate/`) — Main gateway server. Authenticates agents, evaluates policy, injects credentials, proxies requests.
- **wardgate-cli** (`cmd/wardgate-cli/`) — Agent-side HTTP client (curl replacement). Agents use this instead of direct HTTP; it connects to the gateway.
- **wardgate-exec** (`cmd/wardgate-exec/`) — Runs inside isolated conclave environments. Receives commands over WebSocket from the gateway and executes them.

### Request Flow

```
Agent → wardgate-cli → wardgate server → upstream service
                         ↓
              1. Authenticate agent (Bearer token)
              2. Check dynamic grants (time-bound overrides)
              3. Evaluate policy rules (first match wins)
              4. Inject credentials from env vault
              5. Reverse proxy to upstream
              6. Filter sensitive data from response
              7. Audit log the request
```

### Key Packages (`internal/`)

| Package | Purpose |
|---------|---------|
| `policy` | Rule engine — evaluates method/path/command matches, glob patterns, time ranges, rate limits. First-match-wins. |
| `proxy` | HTTP reverse proxy — credential injection, approval integration, response filtering. |
| `config` | YAML config parsing, preset loading, validation. Rejects unknown keys. |
| `auth` | Agent authentication (Bearer/JWT) and credential vault (reads from env vars). |
| `hub` | WebSocket hub for conclave connections. Protocol: welcome/ping/pong/exec/stdout/stderr/exit. |
| `approval` | Async human-in-the-loop approval workflows with timeout. |
| `grants` | Dynamic time-bound policy overrides, persisted to JSON file. |
| `audit` | In-memory request log with configurable size. |
| `filter` | Response filtering — blocks or redacts OTP codes, API keys, tokens. |
| `conclave` | Conclave config and execution logic. |
| `exec` | Shell command parsing (rejects `$()`, backticks, subshells) and template resolution. |
| `notify` | Slack webhook and generic webhook notification channels. |
| `imap` / `smtp` / `ssh` | Protocol-specific adapters with connection pooling. |

### Preset System

`presets/` contains YAML files defining upstream URLs, auth types, and capability-to-rule mappings for common APIs (GitHub, Todoist, etc.). Endpoints reference presets and can override or extend them with custom rules. Capabilities like `read_data: allow` expand into concrete method/path rules.

### Configuration

- Gateway config: `config.yaml` — server settings, agents, endpoints (with policy rules), conclaves, notifications, filters.
- Credentials: `.env` file loaded via `godotenv` — all secrets are environment variables referenced by `*_env` keys in YAML.
- wardgate-cli config: separate `config.yaml` with server URL and agent key.
- wardgate-exec config: separate `config.yaml` with conclave name and key.

### Policy Evaluation

Rules are YAML-defined and evaluated in order (first match wins). Each rule has a `match` (method, path with glob support, command, args regex, cwd pattern) and an `action` (`allow`, `deny`, `ask`, `queue`). Path glob patterns: trailing `*` matches suffix, segment `*` matches one segment, `**` matches zero or more segments.

## Dependencies

Only 4 direct dependencies: `go-imap/v2` (IMAP protocol), `godotenv` (.env loading), `zerolog` (structured logging), `yaml.v3` (config parsing). Indirect: `golang-jwt/jwt/v5`, `gorilla/websocket`, `golang.org/x/crypto`.
