//go:build acceptance

package certificate_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	providerpkg "github.com/entrust/terraform-provider-entrustcagw/internal/provider"
)

func TestAccCertificate_basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC must be set to run acceptance tests")
	}

	baseURL := os.Getenv("ENTRUST_CAGW_BASE_URL")
	clientPath := os.Getenv("ENTRUST_CAGW_CLIENT_P12_PATH")
	clientPassword := os.Getenv("ENTRUST_CAGW_CLIENT_P12_PASSWORD")
	caID := os.Getenv("ENTRUST_CAGW_TEST_CA_ID")
	profileID := os.Getenv("ENTRUST_CAGW_TEST_PROFILE_ID")
	csrPath := os.Getenv("ENTRUST_CAGW_TEST_CSR_PATH")

	if baseURL == "" || clientPath == "" || clientPassword == "" || caID == "" || profileID == "" || csrPath == "" {
		t.Skip("Entrust certificate acceptance environment variables are not configured")
	}

	config := fmt.Sprintf(`
        provider "entrust_cagw" {
          base_url             = %q
          client_p12_path      = %q
          client_p12_password  = %q
        }

        resource "entrust_cagw_certificate" "test" {
          certificate_authority_id = %q
          profile_id               = %q
          csr_pem                  = file(%q)
          rotate_before_days       = 30
          revocation_reason        = "keyCompromise"
        }
    `, baseURL, clientPath, clientPassword, caID, profileID, csrPath)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerpkg.TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("entrust_cagw_certificate.test", "serial_number"),
					resource.TestCheckResourceAttr("entrust_cagw_certificate.test", "status", "issued"),
					resource.TestCheckResourceAttr("entrust_cagw_certificate.test", "rotate_before_days", "30"),
					resource.TestCheckResourceAttrSet("entrust_cagw_certificate.test", "certificate_pem"),
					resource.TestCheckResourceAttrSet("entrust_cagw_certificate.test", "certificate_fingerprint_sha256"),
				),
			},
			{
				ResourceName:      "entrust_cagw_certificate.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}
