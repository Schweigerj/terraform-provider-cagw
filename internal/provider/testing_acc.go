//go:build acceptance

package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestAccProtoV6ProviderFactories exposes provider factories for acceptance tests.
func TestAccProtoV6ProviderFactories() map[string]func() (terraform.Provider, error) {
	return map[string]func() (terraform.Provider, error){
		"entrust_cagw": providerserver.NewProtocol6WithError(New("acc-test")),
	}
}
