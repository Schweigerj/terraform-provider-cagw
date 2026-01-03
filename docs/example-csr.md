# CSR Generation Example

Use `openssl` to generate a private key and CSR compatible with Entrust profiles:

```bash
openssl req \
  -newkey rsa:2048 \
  -keyout server.key \
  -nodes \
  -out server.csr \
  -subj '/CN=app.example.com/O=Example Corp/C=US'
```

Then reference `server.csr` in the Terraform configuration, and store `server.key` securely. For SANs, use `SAN` extensions in the CSR or rely on the profile/plan-time validation for supported prefixes.
