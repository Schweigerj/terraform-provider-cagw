# PKCS#12 Mutual TLS Spike

This spike demonstrates how the provider loads Entrust CA Gateway PKCS#12 credentials and performs a mutual TLS request against the `/v1/ping` endpoint.

## Usage

```bash
export ENTRUST_CAGW_BASE_URL="https://example.cagw.entrust.com"
export ENTRUST_CAGW_CLIENT_P12_PATH="/secure/path/client.p12"
export ENTRUST_CAGW_CLIENT_P12_PASSWORD="super-secret"
export ENTRUST_CAGW_TLS_CA_BUNDLE_PATH="/secure/path/custom-ca.pem" # optional

go run ./spikes/pkcs12
```

The program adds a UUID `X-Correlation-ID` header and logs the HTTP status returned by the ping endpoint.

> ⚠️ Use dedicated development credentials only; never reuse production PKCS#12 bundles for local testing.
