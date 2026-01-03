# Acceptance Testing Guide

The Entrust CA Gateway provider includes acceptance tests (tagged `//go:build acceptance`) that exercise real API calls. These tests are **skipped by default** and should only run against a disposable Entrust environment.

## Required Environment Variables

| Variable | Description |
| --- | --- |
| `TF_ACC` | Must be set to `1` to enable acceptance tests. |
| `ENTRUST_CAGW_BASE_URL` | Entrust CA Gateway base URL (e.g., `https://us.api.entrust.com/cagw/v1`). |
| `ENTRUST_CAGW_CLIENT_P12_PATH` | Path to the PKCS#12 client credential used for mTLS. |
| `ENTRUST_CAGW_CLIENT_P12_PASSWORD` | Password for the PKCS#12 bundle. |
| `ENTRUST_CAGW_TEST_CA_ID` | Certificate authority ID for certificate acceptance tests. |
| `ENTRUST_CAGW_TEST_PROFILE_ID` | Profile ID compatible with the CA. |
| `ENTRUST_CAGW_TEST_CSR_PATH` | Path to a CSR file used for issuance tests. |
| `ENTRUST_CAGW_TEST_PKCS12_PASS` (optional) | Passphrase for PKCS#12 export scenarios. |

## Running Tests

```bash
export TF_ACC=1
export ENTRUST_CAGW_BASE_URL="https://.../v1"
export ENTRUST_CAGW_CLIENT_P12_PATH="/secure/client.p12"
export ENTRUST_CAGW_CLIENT_P12_PASSWORD="example-password"
export ENTRUST_CAGW_TEST_CA_ID="ca-id"
export ENTRUST_CAGW_TEST_PROFILE_ID="profile-id"
export ENTRUST_CAGW_TEST_CSR_PATH="/secure/server.csr"

# Ping data source acceptance test
go test -tags=acceptance ./internal/provider -run TestAccEntrustPingDataSource

# Certificate lifecycle acceptance test
go test -tags=acceptance ./internal/resources/certificate -run TestAccCertificate_basic
```

**Warning:** These tests create and revoke real certificates. Only run them in a controlled environment with disposable credentials.
