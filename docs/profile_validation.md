# Profile-Based Validation

Entrust profiles describe key algorithm, length, and SAN requirements that your Terraform plans should respect. Starting with the current provider build, the `entrust_cagw_certificate` resource can optionally accept `csr_key_type` and `csr_key_length` inputs so it can validate those properties against the selected profile.

## Recommended Workflow

```hcl
data "entrust_cagw_profile" "server" {
  profile_id = var.profile_id
}

resource "entrust_cagw_certificate" "server" {
  certificate_authority_id = var.ca_id
  profile_id               = data.entrust_cagw_profile.server.id
  csr_pem                  = file(var.csr_path)
  csr_key_type             = var.csr_key_type
  csr_key_length           = var.csr_key_length

  subject_alternative_names = var.sans
}
```

- When `csr_key_type` / `csr_key_length` are provided, plan-time validation ensures the values exist in the profile’s `key_types` / `key_lengths` list.
- SAN validation happens automatically (intersection of tenant capabilities and profile `san_types`).

## Pre-Provider Validation (Optional)

You can still use native Terraform preconditions for additional guarantees (for example, comparing against the raw `data.entrust_cagw_profile.server.key_types` value or applying custom logic).

## Future Work

A future iteration will call Entrust’s validation endpoint directly (e.g., via a `validate_only` flag) to confirm CSR compatibility without issuing certificates. See `docs/validate_only.md` for the planned design.
