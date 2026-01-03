package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/entrust/terraform-provider-entrustcagw/internal/provider"
)

var (
	// version is overwritten by goreleaser at build time.
	version = "dev"
)

func main() {
	if err := providerserver.Serve(
		context.Background(),
		provider.New(version),
		providerserver.ServeOpts{
			Address: "registry.terraform.io/entrust/cagw",
		},
	); err != nil {
		log.Fatalf("error starting provider: %v", err)
	}
}
