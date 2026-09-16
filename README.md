# JWT Validator (Go)

A command-line tool that reads a directory of JWT files and validates each one concurrently — checking signature, expiry, algorithm whitelist, `kid` allowlist, and required claims. Built as a hands-on way to learn Go's concurrency model, and directly paired with [jwt-attack-lab](https://github.com/Snitch-1302/jwt-attack-lab): every defense here exists to reject a specific forged token from that project.

> Status: **in progress**. Single-token validation logic (signature, expiry, algorithm whitelist, `kid` allowlist, required claims) is complete. Directory-wide concurrent processing and reporting are not yet built. This README reflects the current state of the code.

## Why this exists

The attack lab spent six stages breaking JWT verification in a Flask API. This project flips the direction: instead of finding new ways to bypass a verifier, it builds one verifier that's supposed to hold up against the same attack payloads — signed by the same forged-token generators, this time getting rejected instead of accepted. It's also a deliberate vehicle for learning Go's `sync`/goroutine/channel model from scratch, rather than defaulting to a language already comfortable.

## Tech stack

- Go 1.21
- [`golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) — JWT parsing and verification
- Standard library: `os`, `strings`, `sync` (concurrency, not yet added)

## Project structure

```
jwt-validator/
├── main.go          # Entry point — directory scan + token validation logic
├── tokens/          # Test JWT files (.jwt) — not committed if they contain real secrets
├── go.mod
├── go.sum
└── README.md
```

## Setup

```
git clone https://github.com/Snitch-1302/jwt-validator.git
cd jwt-validator
go mod tidy
```

## Run

```
go run main.go
```

Currently reads every `.jwt` file in a `tokens/` folder (created manually) and validates the first one found against a hardcoded path — directory-wide looping is the next stage.

## Validation checks implemented

- [x] **Signature verification** — rejects any token whose signature doesn't match the expected secret, via `jwt.Parse`'s `Keyfunc` callback.
- [x] **Expiry enforcement** — handled automatically by `golang-jwt` when an `exp` claim is present; a token past its expiry is rejected with a clear error.
- [x] **Algorithm whitelist** — the token's claimed algorithm (`token.Method.Alg()`) is checked against an explicit list *before* a verification key is ever returned, directly defeating `alg: none` and similar bypass attempts. See [attack-lab Part 3](https://quietbytes.hashnode.dev/jwt-attack-lab-part-3-alg-none-bypass).
- [x] **`kid` allowlist** — the token's `kid` header (if present) is checked against a hardcoded allowlist inside the same `Keyfunc`, before any key lookup happens — defeating `kid`-based path traversal / injection. See [attack-lab Part 5](https://quietbytes.hashnode.dev/jwt-attack-lab-part-5-kid-injection).
- [x] **Required claims check** — after successful parsing, the token's claims are checked for the presence of required fields (`sub`, `exp`); a structurally valid but incomplete token is rejected.
- [ ] **Directory-wide validation** — currently validates one hardcoded file; looping over every discovered `.jwt` file is next.
- [ ] **Concurrency** — goroutines + WaitGroup + channel to validate multiple tokens in parallel, the core learning goal of this project.
- [ ] **Per-token report output** — a clean, aggregated summary of every token's validation result.

## Not covered (and why)

- **Weak-secret / brute-forceable HMAC keys** — a validator can't judge the entropy of a secret it's handed; this is a generation-time and secrets-management concern, not something checkable at validation time. See [attack-lab Part 4](https://quietbytes.hashnode.dev/jwt-attack-lab-part-4-hmac-hashcat).
- **JWKS spoofing defense** — would require fetching a trusted JWKS URL over the network and reconstructing a key from it. Deliberately deferred: it introduces genuine I/O-bound concurrency (waiting on network latency) as opposed to this project's current CPU-bound goroutine use case, and is planned as a follow-up piece once the core concurrency model is solid. See [attack-lab Part 6](https://quietbytes.hashnode.dev/jwt-attack-lab-part-6-spoofing-the-jwks-url-an-rsa-verifier-trusts).

## Related

- [jwt-attack-lab](https://github.com/Snitch-1302/jwt-attack-lab) — the companion project this validator defends against.
- Hashnode write-up: *(link added once published)*

## Disclaimer

Educational project. Not intended for production use as-is.
