# Entrust CA Gateway Terraform Provider

Terraform provider for automating Entrust CA Gateway (CAGW) certificate management with mutual TLS authentication.

> **Status:** Experimental. Focused on provider scaffolding, TLS/authentication plumbing, and the first read-only data sources prior to implementing certificate issuance resources.

## Features (current)

- Provider configuration for Entrust CA Gateway, including base URL selection, mTLS PKCS#12 credentials, optional custom trust bundles, proxy support, and per-request correlation IDs.
- Shared HTTP client with request tracing, retries (future), and helpers for new data sources/resources.
- `entrust_cagw_ping` data source to verify credentials and environment wiring.
- `entrust_cagw_certificate_authorities` data source returning all CAs visible to the calling credentials.
- `entrust_cagw_certificate_authority` data source retrieving details for a single CA.
- PKCS#12 spike (`spikes/pkcs12`) demonstrating low-level TLS handshake testing independent of Terraform.
- Product/engineering plan capturing scope, roadmap, and MVP DoD (`docs/entrust_cagw_provider_plan.md`).

## Roadmap (short-term)

1. Complete coverage for Entrust read-only APIs (profiles, certificates, capabilities).
2. Implement the `entrust_cagw_certificate` resource (CSR + optional PKCS#12 issuance, revoke-on-destroy).
3. Add unit tests for provider config, TLS loader, and each data source using `httptest.Server`.
4. Wire up acceptance tests gated behind environment variables for real tenants.

See the detailed plan in `docs/entrust_cagw_provider_plan.md` for full milestones and epics.

## Getting Started

```bash
# Ensure Go 1.22+ is installed
git clone https://github.com/<your-account>/terraform-provider-entrustcagw.git
cd terraform-provider-entrustcagw

# Install dependencies and run tests
go test ./...

# Build the provider binary
go build -o bin/terraform-provider-entrustcagw ./cmd/terraform-provider-entrustcagw
```

To exercise the PKCS#12 spike:

```bash
export ENTRUST_CAGW_BASE_URL="https://example.cagw.entrust.com/v1"
export ENTRUST_CAGW_CLIENT_P12_PATH="/secure/path/client.p12"
export ENTRUST_CAGW_CLIENT_P12_PASSWORD="super-secret"
go run ./spikes/pkcs12
```

## Development

- `internal/client`: low-level HTTP + TLS utilities and API-facing helpers.
- `internal/provider`: Terraform Plugin Framework provider implementation.
- `internal/datasources`: Data source packages (ping, certificate authorities, etc.).
- `spikes/`: Throwaway experiments validating tricky behaviors (TLS, revocation, etc.).
- `docs/`: Product planning artifacts and future design notes.

Use `gofmt`/`golangci-lint` before committing and keep new code covered by unit or acceptance tests where practical.

## Testing Strategy

| Test Type           | Tooling                          | Notes |
|---------------------|----------------------------------|-------|
| Unit                | `go test ./...` with `httptest`  | Covers provider config, clients, and data sources. |
| Acceptance (future) | `terraform-plugin-testing`       | Requires Entrust tenant credentials; gated via env vars. |

Set `GOCACHE`, `GOPATH`, and `GOMODCACHE` to local directories if running in locked-down environments (examples already baked into dev scripts).

## Security Considerations

- PKCS#12 path/password must point to secure storage; avoid committing credentials.
- `insecure_skip_verify` exists for development-only experimentation, guarded by docs/warnings.
- Optional PKCS#12 export for issued certificates will remain opt-in with strong guidance; default behavior avoids storing private keys in Terraform state.

## License

TBD – choose an appropriate license before publishing the provider (e.g., Apache 2.0).
