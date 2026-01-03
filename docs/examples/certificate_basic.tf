provider "entrust_cagw" {
  base_url              = var.base_url
  client_p12_path       = var.client_p12_path
  client_p12_password   = var.client_p12_password
  tls_ca_bundle_path    = var.tls_ca_bundle_path
}

data "entrust_cagw_certificate_authority" "example" {
  certificate_authority_id = var.certificate_authority_id
}

resource "entrust_cagw_certificate" "example" {
  certificate_authority_id = data.entrust_cagw_certificate_authority.example.id
  profile_id               = var.profile_id
  csr_pem                  = file(var.csr_path)

  subject_alternative_names = [
    "dns:${var.hostname}",
    "ip:${var.service_ip}",
  ]

  rotate_before_days = 30
  revoke_on_destroy  = true
  revocation_reason  = "keyCompromise"
}

output "issued_certificate_pem" {
  value     = entrust_cagw_certificate.example.certificate_pem
  sensitive = true
}

output "issued_fingerprint_sha256" {
  value = entrust_cagw_certificate.example.certificate_fingerprint_sha256
}
