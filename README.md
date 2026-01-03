# Entrust CA Gateway Terraform Provider

Terraform provider for automating Entrust CA Gateway (CAGW) certificate management with mutual TLS authentication.

> **Status:** Experimental. Focused on provider scaffolding, TLS/authentication plumbing, and the first read-only data sources prior to implementing certificate issuance resources.

## Features (current)

- Provider configuration for Entrust CA Gateway, including base URL selection, mTLS PKCS#12 credentials, optional custom trust bundles, proxy support, and per-request correlation IDs.
- Shared HTTP client with request tracing, automatic 429 backoff/retries, rich diagnostics (correlation IDs surfaced in errors), and helper methods for data sources/resources.
- `entrust_cagw_ping` data source to verify credentials and environment wiring.
- `entrust_cagw_certificate_authorities` data source returning all CAs visible to the calling credentials.
- `entrust_cagw_certificate_authority` data source retrieving details for a single CA.
- `entrust_cagw_profiles` / `entrust_cagw_profile` data sources exposing enrollment requirements.
- `entrust_cagw_capabilities` data source for plan-time validation of SAN/key/PKCS#12 support.
- `entrust_cagw_certificate` data source and resource for issuing CSR-based certificates, optional PKCS#12 exports (opt-in), lifecycle controls (`revoke_on_destroy`, `hold_on_destroy`, `revocation_reason`), and proactive rotation via `rotate_before_days`.
- Computed certificate outputs include PEM body, issuer chain, SHA-1/SHA-256 fingerprints, validity timestamps, and the effective SAN set, making downstream integrations deterministic.
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

See `docs/examples/certificate_basic.tf` for a minimal CSR issuance flow that wires together the provider, CA lookup, lifecycle flags/rotation, and the `entrust_cagw_certificate` resource.

### Lifecycle & Rotation Controls

```hcl
resource "entrust_cagw_certificate" "web" {
  certificate_authority_id = data.entrust_cagw_certificate_authority.selected.id
  profile_id               = var.profile_id
  csr_pem                  = file(var.csr_path)

  # Optional SAN inputs (validated at plan time)
  subject_alternative_names = [
    "dns:${var.hostname}",
    "ip:${var.service_ip}",
  ]

  # Lifecycle controls
  rotate_before_days = 30
  revoke_on_destroy  = true
  hold_on_destroy    = false
  revocation_reason  = "keyCompromise"
}

output "issued_fingerprint_sha256" {
  value = entrust_cagw_certificate.web.certificate_fingerprint_sha256
}
```

- `revoke_on_destroy` defaults to `true` to ensure certificates are revoked when removed from state. Set it to `false` for imports or externally managed lifecycles.
- `hold_on_destroy` triggers a certificate hold (only when tenant capabilities advertise support). It automatically ignores any `revocation_reason`.
- `rotate_before_days` uses the issued certificate’s `not_after` timestamp to force replacement when an apply occurs inside the chosen window.
- Computed attributes such as `certificate_fingerprint_sha256`, `certificate_pem`, `certificate_chain_pem`, `subject_dn`, `not_before`, and `not_after` make it easy to export artifacts into Vault, Kubernetes secrets, etc.

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

### Plan-Time Validation & Capabilities

- The provider surfaces `entrust_cagw_capabilities` to expose tenant features such as supported SAN types, key algorithms, and PKCS#12 availability.
- The `entrust_cagw_certificate` resource performs plan-time validation using these capabilities:
  - Blocks unsupported SAN type prefixes (values must be `type:value`, e.g., `dns:example.com`).
  - Ensures PKCS#12 generation is only enabled when the tenant advertises support and a passphrase is provided.
- When a `profile_id` is supplied, the resource also validates SAN entries against the profile's own SAN requirements, preventing mismatches before apply.
- Additional profile-specific validation (key types, SAN requirements) can be layered in Terraform using the profile data sources returned by Entrust.

## Security Considerations

- PKCS#12 path/password must point to secure storage; avoid committing credentials.
- `insecure_skip_verify` exists for development-only experimentation, guarded by docs/warnings.
- Optional PKCS#12 export for issued certificates will remain opt-in with strong guidance; default behavior avoids storing private keys in Terraform state.
- Lifecycle flags (`revoke_on_destroy`, `hold_on_destroy`, `revocation_reason`) are validated against tenant capabilities to prevent accidental skips or unsupported options. Destroy defaults to revocation unless explicitly disabled.
- Rotation happens entirely on the Entrust side—private keys are never written to Terraform state (unless PKCS#12 output is explicitly enabled).

- See `docs/pkcs12_guidance.md` for detailed recommendations on enabling PKCS#12 output, securing passphrases, handling sensitive Terraform state, and pairing the feature with `revocation_reason`/`rotate_before_days`.
- Refer to `docs/acceptance.md` for instructions on configuring `TF_ACC` runs and the required Entrust environment variables.
- Consult `docs/profile_validation.md` and `docs/example-csr.md` for additional guidance on profile-aware planning and CSR generation workflows.
- When `csr_key_type` / `csr_key_length` inputs are provided on `entrust_cagw_certificate`, the provider validates them against the profile metadata to prevent unsupported key algorithms or lengths at plan time.

## Acceptance Testing Strategy

- Acceptance tests will use `terraform-plugin-testing` to exercise create/read/delete/import flows against a real Entrust tenant.
- Required environment variables (mirroring data sources and resources) will include:
  - `ENTRUST_CAGW_BASE_URL`
  - `ENTRUST_CAGW_CLIENT_P12_PATH`
  - `ENTRUST_CAGW_CLIENT_P12_PASSWORD`
  - `ENTRUST_CAGW_TEST_CA_ID`
  - `ENTRUST_CAGW_TEST_PROFILE_ID`
  - `ENTRUST_CAGW_TEST_CSR_PATH`
- Tests will be gated behind `TF_ACC=1` and will also cover optional PKCS#12 flows when `ENTRUST_CAGW_TEST_PKCS12_PASS` is supplied.
- Run `go test -tags=acceptance ./internal/provider -run TestAcc` to execute acceptance suites once the environment variables are configured.

## License

TBD – choose an appropriate license before publishing the provider (e.g., Apache 2.0).
