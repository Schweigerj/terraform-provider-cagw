package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

func TestExpandStringList(t *testing.T) {
	ctx := context.Background()
	list, diag := types.ListValueFrom(ctx, types.StringType, []string{"a", "b"})
	if diag.HasError() {
		t.Fatalf("unexpected diag: %v", diag)
	}

	values, diags := expandStringList(ctx, list)
	if diags.HasError() {
		t.Fatalf("expandStringList returned diagnostics: %v", diags)
	}

	if len(values) != 2 || values[0] != "a" || values[1] != "b" {
		t.Fatalf("unexpected values: %#v", values)
	}

	empty, diags := expandStringList(ctx, types.ListNull(types.StringType))
	if diags.HasError() {
		t.Fatalf("expandStringList null returned diagnostics: %v", diags)
	}
	if empty != nil {
		t.Fatalf("expected nil slice for null list")
	}
}

func TestFlattenCertificate(t *testing.T) {
	ctx := context.Background()
	certPEM, rawCert := generateTestCertificate(t)
	cert := &client.Certificate{
		SerialNumber:            "ABC123",
		Status:                  "issued",
		SubjectDN:               "CN=example",
		IssuerDN:                "CN=Entrust",
		SubjectAlternativeNames: []string{"dns:example.com"},
		NotBefore:               "2024-01-01T00:00:00Z",
		NotAfter:                "2025-01-01T00:00:00Z",
		CertificatePEM:          certPEM,
		CertificateChainPEM:     []string{certPEM},
		RevocationReason:        "",
		PKCS12:                  "c29tZS1wazEy",
		CreatedAt:               "2024-01-01T00:00:00Z",
		UpdatedAt:               "2024-01-01T00:00:00Z",
	}

	state, diags := flattenCertificate(ctx, cert)
	if diags.HasError() {
		t.Fatalf("flattenCertificate returned diagnostics: %v", diags)
	}

	if state.SerialNumber.ValueString() != "ABC123" {
		t.Fatalf("unexpected serial number: %s", state.SerialNumber.ValueString())
	}
	if state.SubjectDN.ValueString() != "CN=example" {
		t.Fatalf("unexpected subject dn: %s", state.SubjectDN.ValueString())
	}
	if state.CertificateChainPEM.IsNull() || state.CertificateChainPEM.IsUnknown() {
		t.Fatalf("expected certificate chain to be populated")
	}
	if state.PKCS12Base64.IsNull() || state.PKCS12Base64.ValueString() != "c29tZS1wazEy" {
		t.Fatalf("expected PKCS#12 value to be set")
	}

	sha1Sum := sha1.Sum(rawCert)
	sha256Sum := sha256.Sum256(rawCert)
	expectedSHA1 := strings.ToUpper(hex.EncodeToString(sha1Sum[:]))
	expectedSHA256 := strings.ToUpper(hex.EncodeToString(sha256Sum[:]))

	if state.CertificateFingerprintSHA1.IsNull() || state.CertificateFingerprintSHA1.ValueString() != expectedSHA1 {
		t.Fatalf("unexpected SHA-1 fingerprint: %s", state.CertificateFingerprintSHA1.ValueString())
	}
	if state.CertificateFingerprintSHA256.IsNull() || state.CertificateFingerprintSHA256.ValueString() != expectedSHA256 {
		t.Fatalf("unexpected SHA-256 fingerprint: %s", state.CertificateFingerprintSHA256.ValueString())
	}
}

func TestValidateSubjectAlternativeNames(t *testing.T) {
	ctx := context.Background()
	caps := &client.Capabilities{
		SupportedSANTypes: []string{"dns", "ip"},
	}

	list, diag := types.ListValueFrom(ctx, types.StringType, []string{"dns:example.com", "email:admin"})
	if diag.HasError() {
		t.Fatalf("unexpected diag: %v", diag)
	}

	diags := validateSubjectAlternativeNames(ctx, caps, nil, list)
	if !diags.HasError() {
		t.Fatalf("expected diagnostics for unsupported SAN type")
	}
}

func TestValidateSubjectAlternativeNamesProfileIntersection(t *testing.T) {
	ctx := context.Background()
	caps := &client.Capabilities{
		SupportedSANTypes: []string{"dns", "ip"},
	}
	profile := &client.Profile{
		SANTypes: []string{"dns"},
	}

	list, diag := types.ListValueFrom(ctx, types.StringType, []string{"ip:10.0.0.1"})
	if diag.HasError() {
		t.Fatalf("unexpected diag: %v", diag)
	}

	diags := validateSubjectAlternativeNames(ctx, caps, profile, list)
	if !diags.HasError() {
		t.Fatalf("expected diagnostics for unsupported SAN type")
	}
}

func TestValidateKeyRequirements(t *testing.T) {
	profile := &client.Profile{
		ID:         "profile-1",
		KeyTypes:   []string{"rsa"},
		KeyLengths: []int{2048},
	}

	parsed := &csrAttributes{KeyType: "ecdsa", KeyLength: 1024}
	diags := validateKeyRequirements(profile, parsed, types.StringNull(), types.Int64Null())
	if len(diags) != 2 {
		t.Fatalf("expected two diagnostics, got %d", len(diags))
	}

	parsed = &csrAttributes{KeyType: "rsa", KeyLength: 2048}
	diags = validateKeyRequirements(profile, parsed, types.StringNull(), types.Int64Null())
	if diags.HasError() {
		t.Fatalf("expected no diagnostics for supported key requirements")
	}
}

func TestValidateLifecycleOptionsHoldUnsupported(t *testing.T) {
	config := resourceModel{
		RevokeOnDestroy: types.BoolValue(true),
		HoldOnDestroy:   types.BoolValue(true),
	}
	caps := &client.Capabilities{SupportsCertificateHold: false}

	diags := validateLifecycleOptions(config, caps)
	if !diags.HasError() {
		t.Fatalf("expected error when hold_on_destroy is true but capability disabled")
	}
}

func TestValidateLifecycleOptionsInvalidReason(t *testing.T) {
	config := resourceModel{
		RevokeOnDestroy:  types.BoolValue(true),
		RevocationReason: types.StringValue("notAReason"),
	}

	diags := validateLifecycleOptions(config, nil)
	if !diags.HasError() {
		t.Fatalf("expected diagnostics for unsupported revocation reason")
	}
}

func generateTestCertificate(t *testing.T) (string, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("creating x509 certificate: %v", err)
	}

	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		t.Fatalf("failed to encode certificate to PEM")
	}

	return string(pemBytes), der
}
