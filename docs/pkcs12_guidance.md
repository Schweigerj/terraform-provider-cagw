# PKCS#12 Handling Guidance

The Entrust CA Gateway provider exposes optional PKCS#12 support on the `entrust_cagw_certificate` resource. This feature is disabled by default and should only be enabled when you explicitly need Entrust to generate key material.

## Enablement

```hcl
resource "entrust_cagw_certificate" "server" {
  # ... standard CSR inputs ...
  generate_pkcs12   = true
  pkcs12_passphrase = var.pkcs12_passphrase
}
```

- `generate_pkcs12` is _opt-in_ and requires a passphrase.
- The passphrase should come from a secure secret store (e.g., Terraform Cloud sensitive variable, Vault, or environment-specific secret management).
- Plan-time validation prevents enablement when the tenant’s capabilities do not support PKCS#12 export.

## Terraform State Considerations

- When enabled, the provider stores the base64-encoded PKCS#12 blob in the sensitive attribute `pkcs12_base64`.
- Because Terraform state captures this value, restrict state access (Terraform Cloud workspaces, encrypted backend, etc.).
- Rotate PKCS#12 credentials frequently and avoid committing state files to source control.

## Suggested Workflow

1. Prefer CSR-based issuance with client-generated keys whenever possible.
2. If PKCS#12 is required (e.g., legacy systems), enable `generate_pkcs12` only for those resources.
3. Consume the `pkcs12_base64` output with downstream tooling that can securely decode and store the PKCS#12 payload.
4. Consider stripping PKCS#12 data from state after provisioning (for example, by moving the artifact to a secrets manager and removing the attribute via `terraform state rm` once exported).

## Additional Tips

- Combine PKCS#12 flags with `revocation_reason = "keyCompromise"` so the certificate explicitly revokes on destroy.
- Pair `generate_pkcs12` with `rotate_before_days` so Terraform proactively renews server-generated keys before they expire (without ever storing private key material locally).
- If the tenant advertises certificate-hold support, `hold_on_destroy = true` can be used for temporary suspensions instead of irreversible revocation.
- Leverage `entrust_cagw_capabilities` to confirm tenant support before enabling PKCS#12 for entire environments.
- Use separate Terraform workspaces (or modules) for PKCS#12-generating resources to limit state blast radius.
