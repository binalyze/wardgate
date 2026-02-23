# Plan: Sealed Credentials Feature

## Context

Wardgate currently supports two ways to provide upstream API credentials:
1. **Static credentials** (`credential_env`) — Wardgate reads API keys from its own environment/vault
2. **JWT agent auth** — authenticates the agent TO Wardgate, but upstream creds still come from the vault

When running agents in sandboxed environments (conclaves), the operator must manage every upstream API key on the Wardgate server. This doesn't scale when agents need individual API keys for multiple services.

**Sealed Credentials** solves this: the operator encrypts upstream API keys using a shared seal key, gives the encrypted values to agents, and agents send them as `X-Wardgate-Sealed-*` prefixed headers. Wardgate strips the prefix, decrypts the values, and forwards them as regular headers to the upstream. Even if an agent dumps the encrypted values, they're useless without the seal key (which lives only on the Wardgate server).

## Design

### Core idea: prefix-based header passthrough

The agent decides what headers the upstream API needs. It prefixes each header name with `X-Wardgate-Sealed-` and encrypts the value. Wardgate strips the prefix, decrypts, and forwards.

**No mapping config needed.** The agent is in full control of what headers reach upstream.

```
Agent sends:
  X-Wardgate-Sealed-Authorization: <encrypt("Bearer ghp_realtoken")>
  X-Wardgate-Sealed-X-Api-Key:     <encrypt("key_12345")>

Wardgate processes:
  Strip prefix  →  Authorization, X-Api-Key
  Decrypt value →  "Bearer ghp_realtoken", "key_12345"

Upstream receives:
  Authorization: Bearer ghp_realtoken
  X-Api-Key: key_12345
```

This works for any auth scheme: Bearer tokens, API keys, Basic auth, custom headers, usernames — whatever the upstream API expects. The agent composes the full header value (including "Bearer " prefix if needed) and Wardgate just decrypts and forwards.

### Request flow

```
Operator: wardgate seal "Bearer ghp_realtoken"  →  "base64(nonce+ciphertext)"
           ↓ gives encrypted value to agent as env var

Agent request to Wardgate:
  Authorization: Bearer <jwt-for-wardgate-auth>
  X-Wardgate-Sealed-Authorization: <encrypted-value>
  →  POST /github/repos/owner/repo/issues

Wardgate:
  1. JWT auth validates agent identity                           ✓
  2. Sees endpoint github has auth.sealed: true
  3. Finds all X-Wardgate-Sealed-* headers on the request
  4. For each sealed header:
     a. Strip "X-Wardgate-Sealed-" prefix → real header name
     b. Check decryption cache (key = ciphertext)
        - HIT:  use cached plaintext
        - MISS: decrypt via AES-256-GCM, cache with TTL
     c. Set the real header with decrypted value on outgoing request
  5. Strip all X-Wardgate-Sealed-* headers (don't leak to upstream)
  6. Strip agent's Authorization header (it's for Wardgate, not upstream)
  7. Proxy to api.github.com
```

### Config

```yaml
server:
  listen: :8080
  jwt:
    secret_env: JWT_SECRET
  seal:                              # NEW
    key_env: WARDGATE_SEAL_KEY       # 32-byte hex-encoded AES-256 key
    cache_ttl: 5m                    # how long to cache decrypted values (default: 5m)

endpoints:
  github:
    upstream: https://api.github.com
    auth:
      sealed: true                   # NEW: credentials come from agent's sealed headers
    rules: [...]

  # Existing static credential endpoints continue to work unchanged
  todoist:
    upstream: https://api.todoist.com
    auth:
      type: bearer
      credential_env: TODOIST_TOKEN
    rules: [...]
```

When `sealed: true`:
- `type` and `credential_env` are NOT required (agent provides everything)
- The proxy reads `X-Wardgate-Sealed-*` headers instead of vault lookup
- All policy evaluation (rules, grants, rate limits) still applies normally

### Decryption cache

Built into the `Sealer` struct. Avoids repeated AES-GCM decryption for the same sealed values across requests.

- **Key**: sealed ciphertext string (same ciphertext → same plaintext, deterministic)
- **Value**: decrypted plaintext + expiry timestamp
- **TTL**: configurable via `seal.cache_ttl` (default 5m, should be < JWT lifetime)
- **Eviction**: lazy check on read + periodic background sweep
- **Thread safety**: `sync.RWMutex` (concurrent reads, exclusive writes)

```go
type cacheEntry struct {
    plaintext string
    expiresAt time.Time
}

type Sealer struct {
    key      []byte
    cacheTTL time.Duration
    mu       sync.RWMutex
    cache    map[string]cacheEntry
    done     chan struct{}   // stops background sweeper
}
```

### Encryption: AES-256-GCM

- Standard authenticated encryption (Go stdlib `crypto/aes` + `crypto/cipher`)
- Seal key: 32 bytes, stored as hex in env var
- Sealed format: `base64(12-byte-nonce || ciphertext || GCM-tag)`
- No new dependencies required

## Implementation Steps

### Step 1. New package `internal/seal/`

**Why first**: self-contained, no dependencies on other packages. Foundation for everything else.

**`internal/seal/seal.go`**:

```go
type Sealer struct { ... }

func New(hexKey string, cacheTTL time.Duration) (*Sealer, error)
func (s *Sealer) Encrypt(plaintext string) (string, error)   // used by CLI seal command
func (s *Sealer) Decrypt(sealed string) (string, error)      // checks cache → decrypt on miss
func (s *Sealer) Stop()                                      // stops background cache sweeper
```

Implementation details:
- `New`: hex-decode key, validate 32 bytes, init AES-GCM cipher, start sweeper goroutine
- `Encrypt`: generate random 12-byte nonce, encrypt, return base64(nonce || ciphertext)
- `Decrypt`: check cache first (RLock). On miss, base64-decode, split nonce, decrypt (Lock), store in cache
- Sweeper: runs every `cacheTTL` interval, removes expired entries under write lock

**`internal/seal/seal_test.go`**:
- Roundtrip encrypt/decrypt
- Invalid key length (not 32 bytes)
- Tampered ciphertext → error
- Empty plaintext handling
- Cache hit verification (decrypt called twice, second should be cached)
- Cache expiry (set short TTL, verify entry expires)
- Concurrent access (goroutine safety with -race)

### Step 2. Config changes — `internal/config/config.go`

**Add structs and fields**:

```go
type SealConfig struct {
    KeyEnv   string `yaml:"key_env"`
    CacheTTL string `yaml:"cache_ttl,omitempty"` // Go duration, default "5m"
}
```

- Add `Seal *SealConfig` to `ServerConfig`
- Add `Sealed bool` to `AuthConfig`

**Validation changes in `validate()`**:
- When `sealed: true`: skip requiring `type` and `credential_env`
- When `sealed: true` AND `credential_env` is set: error (mutually exclusive)
- When `sealed: true`: require `server.seal` to be configured
- When `cache_ttl` is set: validate it parses as a Go duration

**`ValidateEnv()` changes**:
- If `server.seal` is configured, validate `key_env` env var is set

### Step 3. Proxy changes — `internal/proxy/http.go`

**Struct changes**:
- Add `sealer *seal.Sealer` field to `Proxy`
- Add `SetSealer(s *seal.Sealer)` method

**`ServeHTTP` changes** — after policy evaluation, before creating reverse proxy:

```go
// Get credential(s)
var cred string
if p.endpoint.Auth.Sealed {
    // Sealed headers are processed in the Director (below)
    // Validate at least one sealed header is present
    hasSealedHeader := false
    for name := range r.Header {
        if strings.HasPrefix(strings.ToLower(name), "x-wardgate-sealed-") {
            hasSealedHeader = true
            break
        }
    }
    if !hasSealedHeader {
        http.Error(w, "missing X-Wardgate-Sealed-* headers", http.StatusBadRequest)
        return
    }
} else {
    cred, err = p.vault.Get(p.endpoint.Auth.CredentialEnv)
    // ... existing error handling
}
```

**Director function changes** — inside the reverse proxy Director:

```go
Director: func(req *http.Request) {
    req.URL.Scheme = p.upstream.Scheme
    req.URL.Host = p.upstream.Host
    req.URL.Path = p.upstream.Path + r.URL.Path
    req.Host = p.upstream.Host

    if p.endpoint.Auth.Sealed {
        // Process all X-Wardgate-Sealed-* headers
        for name, values := range r.Header {
            if !strings.HasPrefix(name, "X-Wardgate-Sealed-") {
                continue
            }
            realHeader := strings.TrimPrefix(name, "X-Wardgate-Sealed-")
            for _, sealed := range values {
                plaintext, err := p.sealer.Decrypt(sealed)
                if err != nil {
                    // logged; header skipped
                    continue
                }
                req.Header.Set(realHeader, plaintext)
            }
            req.Header.Del(name) // remove sealed header from upstream request
        }
        // Also remove agent's Wardgate auth
        req.Header.Del("Authorization")
    } else if p.endpoint.Auth.Type == "bearer" {
        req.Header.Set("Authorization", "Bearer "+cred)
    }
},
```

### Step 4. Server wiring — `cmd/wardgate/main.go`

In `main()`, after loading config:

```go
var sealer *seal.Sealer
if cfg.Server.Seal != nil {
    cacheTTL := 5 * time.Minute
    if cfg.Server.Seal.CacheTTL != "" {
        cacheTTL, _ = time.ParseDuration(cfg.Server.Seal.CacheTTL)
    }
    sealer, err = seal.New(os.Getenv(cfg.Server.Seal.KeyEnv), cacheTTL)
    if err != nil {
        log.Fatalf("Failed to initialize sealer: %v", err)
    }
    defer sealer.Stop()
    log.Printf("Sealed credentials enabled (cache TTL: %s)", cacheTTL)
}
```

In the HTTP proxy creation block:

```go
p := proxy.NewWithName(name, endpoint, vault, engine)
if sealer != nil {
    p.SetSealer(sealer)
}
```

### Step 5. CLI `seal` subcommand — `cmd/wardgate/main.go`

Add `"seal"` to the subcommand switch:

```
wardgate seal <plaintext-value>
# Reads WARDGATE_SEAL_KEY from .env / process env
# Prints: <base64-sealed-value>
```

Implementation:
1. Load .env file
2. Read `WARDGATE_SEAL_KEY` from env
3. Create sealer (cache doesn't matter for one-shot encrypt)
4. Encrypt the argument
5. Print sealed value to stdout

### Step 6. Tests

**`internal/seal/seal_test.go`** (new):
- `TestEncryptDecrypt` — roundtrip
- `TestInvalidKeyLength` — short/long key rejected
- `TestTamperedCiphertext` — modified sealed string fails
- `TestDecryptCache` — second call uses cache (verify with counter or mock)
- `TestCacheExpiry` — short TTL, sleep, verify re-decryption
- `TestConcurrentDecrypt` — parallel goroutines with -race

**`internal/config/config_test.go`** (add cases):
- Valid sealed endpoint (sealed: true, no credential_env)
- `sealed: true` without `server.seal` → error
- `sealed: true` with `credential_env` → error

**`internal/proxy/http_test.go`** (add cases):
- Sealed proxy: request with `X-Wardgate-Sealed-Authorization` → upstream gets `Authorization`
- Sealed proxy: multiple sealed headers → all forwarded
- Sealed proxy: missing sealed headers → 400
- Sealed proxy: invalid encrypted value → error handling

## Files to modify

| File | Change |
|------|--------|
| `internal/seal/seal.go` | **NEW** — AES-256-GCM encrypt/decrypt + TTL cache |
| `internal/seal/seal_test.go` | **NEW** — Seal package tests |
| `internal/config/config.go` | Add `SealConfig`, `Sealed` field, validation |
| `internal/config/config_test.go` | Add sealed config validation tests |
| `internal/proxy/http.go` | Sealed header processing + header stripping |
| `internal/proxy/http_test.go` | Add sealed proxy tests |
| `cmd/wardgate/main.go` | Sealer creation, wiring, `seal` subcommand |

## Verification

```bash
# Run all tests
go test -v -race ./...

# Specifically test the new seal package
go test -v -race ./internal/seal/

# Test config validation
go test -v -race -run TestSealed ./internal/config/

# Test proxy sealed flow
go test -v -race -run TestSealed ./internal/proxy/

# Build all binaries
go build -v ./...
```

## Example usage (end-to-end)

```bash
# 1. Operator generates seal key
export WARDGATE_SEAL_KEY=$(openssl rand -hex 32)

# 2. Operator encrypts a GitHub token for an agent
wardgate seal "Bearer ghp_agent1_github_token"
# → prints: c2VhbGVkX1...base64...

# 3. Agent's sandbox environment has:
#    - JWT for Wardgate auth
#    - Encrypted GitHub token as env var
#    GITHUB_SEALED=c2VhbGVkX1...base64...

# 4. Agent makes request via wardgate-cli
wardgate-cli \
  -H "X-Wardgate-Sealed-Authorization: $GITHUB_SEALED" \
  https://api.github.com/repos/owner/repo

# 5. Wardgate receives:
#    Authorization: Bearer <jwt>             → validates agent
#    X-Wardgate-Sealed-Authorization: <enc>  → decrypts
#
#    Upstream receives:
#    Authorization: Bearer ghp_agent1_github_token
```
