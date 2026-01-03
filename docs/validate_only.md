# Validate-Only Mode (Planned)

Entrust's profile capabilities expose validation endpoints that confirm CSR/SAN/key combinations without issuing a certificate. The Terraform provider will eventually surface this as a `validate_only` flag on `entrust_cagw_certificate` so teams can dry-run their requests before touching the issuance quota.

## Proposed Workflow

```hcl
resource "entrust_cagw_certificate" "server" {
  certificate_authority_id = var.ca_id
  profile_id               = var.profile_id
  csr_pem                  = file(var.csr_path)
  validate_only            = true
}
```

- When `validate_only = true`, the resource would call Entrust's validation endpoint and fail the plan/apply if the CSR or SAN set is invalid.
- No certificate would be issued or revoked; Terraform would treat the resource as `tainted` or `computed` so real issuance can happen later.

Until this flag exists, continue using the profile/capabilities data sources alongside manual CSR validation or Entrust tooling.
