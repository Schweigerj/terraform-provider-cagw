# Entrust CA Gateway Terraform Provider Plan

## Phase 0 Clarification Checklist
1. Authentication artifacts: confirm PKCS#12 contents, mutual TLS requirements, and rotation cadence.
2. API base URLs/versioning: validate US/EU hosts, `/v1` prefix, and any sandbox endpoints.
3. Correlation ID conventions: required header name, format constraints, and whether caller-supplied IDs are logged verbatim.
4. Rate limiting: understand quotas/throttling to tune retries/backoff.
5. Scoping rules: identify which endpoints are per-CA versus global.
6. Revocation semantics: capabilities for hold vs revoke, propagation delays, and auditing.
7. PKCS#12 issuance behavior: server-generated key workflow, password policies, transmission rules.
8. Recovery/events/domains maturity: confirm GA status and documentation depth.
9. Logging/audit constraints: metadata requirements for Terraform actions.
10. Test environment provisioning: who supplies tenant credentials/assets for acceptance tests.

## Product Scope
- **MVP**: Provider configuration with mTLS, ping/health data source, read-only data sources (CAs, profiles, certificates, capabilities), `entrust_cagw_certificate` resource (CSR issuance, revoke-on-destroy, import), request correlation IDs, no private keys stored by default.
- **v1 Enhancements**: Optional PKCS#12 output (sensitive base64) with warnings, capability-driven plan validation, validate-only dry runs, hardened retries/proxy support, opinionated modules/examples.
- **Nice-to-have**: Domains/recovery/events coverage once semantics are stable, module library (TLS server cert, k8s mTLS), audit/log export integrations.
- **Explicit Non-goals**: Supporting non-Entrust PKI, managing key material outside issuance/revocation, bulk enrollment scripting inside provider, bypassing mTLS/security constraints.

## Resource & Data Source Catalog
| Name | Type | CRUD | API Endpoints |
| --- | --- | --- | --- |
| `entrust_cagw_ping` | Data | Read | `GET /v1/ping` (or health equivalent) |
| `entrust_cagw_certificate_authorities` | Data | Read | `GET /v1/certificate-authorities` |
| `entrust_cagw_certificate_authority` | Data | Read | `GET /v1/certificate-authorities/{id}` |
| `entrust_cagw_profiles` | Data | Read | `GET /v1/profiles` |
| `entrust_cagw_profile` | Data | Read | `GET /v1/profiles/{id}` |
| `entrust_cagw_certificate` (data) | Data | Read | `GET /v1/certificates/{serial}` |
| `entrust_cagw_capabilities` | Data | Read | `GET /v1/capabilities` or profile-specific capability endpoint |
| `entrust_cagw_certificate` (resource) | Resource | Create, Read, Delete (ForceNew update) | `POST /v1/certificate-authorities/{id}/enrollments`, `GET /v1/certificates/{serial}`, `POST /v1/certificates/{serial}/revoke` or hold |

## Provider Configuration & Security
- `base_url` (string, required): API host including `/v1` path (US/EU examples documented).
- `client_p12_path` (string, required): local filesystem path to the PKCS#12 bundle containing the client cert/key.
- `client_p12_password` (sensitive string, required).
- `tls_ca_bundle_path` (string, optional): custom trust store for enterprise proxies.
- `proxy_url` (string, optional): HTTPS proxy for outbound calls.
- `insecure_skip_verify` (bool, optional): development-only escape hatch; emits a warning when true.
- `correlation_id` (string, optional): default value for the `X-Correlation-ID` header; requests auto-generate UUIDv4 when unset.

**Security Guidance**
- Store PKCS#12/password in secret managers or Terraform sensitive variables (`ENTRUST_CAGW_*` env vars are supported as fallbacks).
- Document rotation cadence and recommend restricted filesystem permissions for PKCS#12 files.
- Highlight risks of enabling `insecure_skip_verify` and PKCS#12 export; both are explicit opt-ins with provider/resource validation.
- Recommend using Terraform Cloud/Enterprise sensitive variables or other encrypted backends for secrets and state.

## State Model & Key Handling
- **Resource ID**: certificate `serial_number` string, stable across lifecycle/import.
- **Inputs**: `certificate_authority_id`, `profile_id`, SAN list, CSR PEM (sensitive), `generate_pkcs12`, `pkcs12_passphrase`, lifecycle flags (`revoke_on_destroy`, `hold_on_destroy`, `revocation_reason`), and `rotate_before_days`.
- **Computed Attributes**: `certificate_pem`, `certificate_chain_pem`, `certificate_fingerprint_sha1`, `certificate_fingerprint_sha256`, `serial_number`, `status`, `subject_dn`, `subject_alternative_names`, `not_before`, `not_after`, `revocation_status_reason`, timestamps, optional `pkcs12_base64`.
- **Sensitive Policy**: No private keys stored by default. Optional PKCS#12 output is stored as sensitive base64 only when `generate_pkcs12 = true`. Documentation steers users toward CSR-only issuance and secure storage for PKCS#12 artifacts.

## Implementation Plan (Go + Terraform Plugin Framework)
1. **Provider Package Structure**
   - `cmd/terraform-provider-entrustcagw/main.go`: entry point.
   - `internal/provider`: schema, configuration parsing, diagnostics helpers.
   - `internal/client`: PKCS#12 loader → `tls.Config`, handcrafted HTTP client with retries/backoff, proxy support, correlation ID middleware, and typed API helpers.
   - `internal/datasources` and `internal/resources`: Terraform Plugin Framework implementations per entity.
   - Shared helpers for diagnostics and CSR parsing live alongside resource packages.

2. **Client/Diagnostics Strategy**
   - Maintain the lightweight handwritten client to keep request/response handling predictable (optionally revisit OpenAPI codegen later).
   - Normalize HTTP errors via `client.APIError`, surfacing status codes and correlation IDs in Terraform diagnostics.
   - Continue mapping TLS/PKCS parsing failures to actionable hints (bad password, missing cert, etc.).

4. **Import Support**
   - Implement `ImportState` for `entrust_cagw_certificate` that sets `serial_number` attribute and calls `Read` to populate state.

## Testing & CI
- **Unit Tests**: `httptest.Server` to simulate API responses; cover config parsing, PKCS#12 loader, HTTP middleware, each data source/resource logic.
- **Acceptance Tests**: `terraform-plugin-testing` with env vars:
  - `ENTRUST_CAGW_BASE_URL`
  - `ENTRUST_CAGW_CLIENT_P12_PATH`
  - `ENTRUST_CAGW_CLIENT_P12_PASSWORD`
  - `ENTRUST_CAGW_TEST_CA_ID`
  - `ENTRUST_CAGW_TEST_PROFILE_ID`
  - `ENTRUST_CAGW_TEST_CSR_PATH`
  - Optional `ENTRUST_CAGW_TEST_PKCS12_PASS` for PKCS#12 acceptance coverage
- **CI Pipeline**: GitHub Actions running gofmt, golangci-lint, unit tests on Go 1.21/1.22 matrix, optional acceptance job gated by secrets, release job using Goreleaser for tagged builds + Terraform Registry publishing.

## Milestones, Risks, Assumptions
- **Phase 0 (1 sprint)**: Confirm auth expectations, fetch/parse OpenAPI, document revocation semantics, run PKCS#12 spike.
- **Phase 1 (1–2 sprints)**: Provider config, HTTP layer, ping + read-only data sources, docs.
- **Phase 2 (2–4 sprints)**: Certificate resource (CSR issuance first), revoke-on-destroy, import, acceptance tests, examples.
- **Phase 3 (ongoing)**: PKCS#12 optional flows, validate-only mode, capability-based validation, DX improvements, optional Domains/Recovery/Events coverage.

**Risks**: Auth variability between tenants, PKCS#12 password policies, revocation propagation delays causing drift, API throttling without documented limits, limited sandbox access.

**Assumptions**: Stable `/v1` endpoints, correlation IDs accepted (likely `X-Correlation-ID`), revocation API synchronous enough for destroy, customers provide CSR by default.

## Epics → Stories → Acceptance Criteria
1. **Provider Foundations**
   - Story: Implement config schema/env overrides. **AC**: Provider loads PKCS#12, constructs `tls.Config`, connects to ping endpoint.
   - Story: HTTP client middleware (timeouts, retries, correlation IDs). **AC**: Requests include header, transient errors retried per policy.
   - Story: Ping/health data source. **AC**: Outputs service version; fails gracefully when unauthorized.
2. **Data Sources**
   - Story: CA list + single lookup. **AC**: Handles pagination/filtering and surfaces metadata.
   - Story: Profiles list/detail. **AC**: Exposes enrollment constraints for plan-time validation.
   - Story: Certificate lookup. **AC**: Fetches by serial or enrollment reference, includes status/revocation fields.
   - Story: Capabilities data source. **AC**: Validates features at plan time, fails fast if unsupported.
3. **Certificate Resource**
   - Story: CSR-based enrollment. **AC**: Create returns certificate PEM, state stores serial.
   - Story: Optional server-generated PKCS#12. **AC**: Only when explicitly enabled; result stored as sensitive base64 with warning.
   - Story: Read/refresh. **AC**: Detects revoked/expired certs and updates status outputs.
   - Story: Delete/revoke. **AC**: Destroy triggers revocation (or hold if configured) and handles API errors gracefully.
   - Story: Import. **AC**: `terraform import` with serial populates state.
4. **DX & Validation**
   - Story: `validate_only` flag. **AC**: Plan surfaces validation output without issuing a cert.
   - Story: Capability-driven schema validation. **AC**: Blocks applies when profile/capability mismatches occur.
   - Story: Documentation/examples. **AC**: Covers CSR issuance, PKCS#12 flow, revoke-on-destroy workflows.

## Definition of Done (MVP)
- Provider config supports required TLS/auth inputs with clear diagnostics.
- Ping and all MVP data sources implemented with documentation and unit + acceptance coverage.
- `entrust_cagw_certificate` resource (CSR flow) supports create/read/delete with revoke-on-destroy, import, and sensitive handling policy enforced.
- Correlation IDs logged for every request.
- Sensitive data guarded; PKCS#12 support opt-in with warnings; docs address secret storage and CI patterns.
- gofmt + golangci-lint clean; unit tests and relevant acceptance tests pass; README/docs include usage examples and security guidance.
