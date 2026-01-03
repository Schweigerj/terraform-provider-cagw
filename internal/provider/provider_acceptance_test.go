//go:build acceptance

package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEntrustPingDataSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acceptance test in short mode")
	}
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC must be set to run acceptance tests")
	}

	baseURL := os.Getenv("ENTRUST_CAGW_BASE_URL")
	clientPath := os.Getenv("ENTRUST_CAGW_CLIENT_P12_PATH")
	clientPassword := os.Getenv("ENTRUST_CAGW_CLIENT_P12_PASSWORD")

	if baseURL == "" || clientPath == "" || clientPassword == "" {
		t.Skip("Entrust acceptance environment variables are not configured")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: TestAccProtoV6ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
                    provider "entrust_cagw" {
                      base_url             = %q
                      client_p12_path      = %q
                      client_p12_password  = %q
                    }

                    data "entrust_cagw_ping" "current" {}
                `, baseURL, clientPath, clientPassword),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.entrust_cagw_ping.current", "status_code"),
				),
			},
		},
	})
}
