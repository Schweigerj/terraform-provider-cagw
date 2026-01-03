package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
	"github.com/entrust/terraform-provider-entrustcagw/internal/datasources/capabilities"
	certificateauthorities "github.com/entrust/terraform-provider-entrustcagw/internal/datasources/certificateauthorities"
	"github.com/entrust/terraform-provider-entrustcagw/internal/datasources/certificates"
	"github.com/entrust/terraform-provider-entrustcagw/internal/datasources/ping"
	"github.com/entrust/terraform-provider-entrustcagw/internal/datasources/profiles"
	"github.com/entrust/terraform-provider-entrustcagw/internal/resources/certificate"
)

// Ensure entrustProvider satisfies the provider.Provider interface.
var _ provider.Provider = (*entrustProvider)(nil)

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &entrustProvider{
			version: version,
		}
	}
}

type entrustProvider struct {
	version string
}

func (p *entrustProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "entrust_cagw"
	resp.Version = p.version
}

func (p *entrustProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Provider for managing Entrust CA Gateway resources.",
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				Required:            true,
				Description:         "Base URL for the Entrust CA Gateway API.",
				MarkdownDescription: "Base URL for the Entrust CA Gateway API (include `/v1`).",
			},
			"client_p12_path": schema.StringAttribute{
				Required:            true,
				Description:         "Filesystem path to the PKCS#12 bundle (client certificate + key).",
				MarkdownDescription: "Filesystem path to the PKCS#12 bundle (client certificate + key).",
				Sensitive:           true,
			},
			"client_p12_password": schema.StringAttribute{
				Required:            true,
				Description:         "Password for decrypting the PKCS#12 bundle.",
				MarkdownDescription: "Password for decrypting the PKCS#12 bundle.",
				Sensitive:           true,
			},
			"tls_ca_bundle_path": schema.StringAttribute{
				Optional:            true,
				Description:         "Optional custom CA bundle used to validate the Entrust CA Gateway endpoint.",
				MarkdownDescription: "Optional custom CA bundle used to validate the Entrust CA Gateway endpoint.",
			},
			"proxy_url": schema.StringAttribute{
				Optional:            true,
				Description:         "Optional HTTPS proxy URL.",
				MarkdownDescription: "Optional HTTPS proxy URL.",
			},
			"insecure_skip_verify": schema.BoolAttribute{
				Optional:            true,
				Description:         "Disable TLS verification (not recommended; only for development).",
				MarkdownDescription: "Disable TLS verification (not recommended; only for development).",
			},
			"correlation_id": schema.StringAttribute{
				Optional:            true,
				Description:         "Correlation ID to include on all requests (UUID recommended).",
				MarkdownDescription: "Correlation ID to include on all requests (UUID recommended).",
			},
		},
	}
}

func (p *entrustProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data, diags := config.expand()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiClient, err := client.New(client.Config{
		BaseURL:            data.BaseURL,
		PKCS12Path:         data.ClientP12Path,
		PKCS12Password:     data.ClientP12Password,
		TLSCABundlePath:    data.TLSCABundlePath,
		ProxyURL:           data.ProxyURL,
		InsecureSkipVerify: data.InsecureSkipVerify,
		CorrelationID:      data.CorrelationID,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to configure Entrust client", err.Error())
		return
	}

	resp.DataSourceData = apiClient
	resp.ResourceData = apiClient
}

func (p *entrustProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		ping.New,
		certificateauthorities.NewList,
		certificateauthorities.NewAuthority,
		profiles.NewList,
		profiles.New,
		certificates.New,
		capabilities.New,
	}
}

func (p *entrustProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		certificate.New,
	}
}
