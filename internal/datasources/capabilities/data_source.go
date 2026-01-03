package capabilities

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

var _ datasource.DataSource = (*DataSource)(nil)

// New returns a capabilities data source.
func New() datasource.DataSource {
	return &DataSource{}
}

// DataSource exposes tenant capabilities for plan-time validation.
type DataSource struct {
	client *client.APIClient
}

func (d *DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_capabilities"
}

func (d *DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves capability flags supported by the Entrust CA Gateway tenant.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Static identifier for the capability set.",
				MarkdownDescription: "Static identifier for the capability set.",
			},
			"supported_san_types": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				Description:         "Subject Alternative Name types supported by the tenant.",
				MarkdownDescription: "Subject Alternative Name types supported by the tenant.",
			},
			"supported_key_types": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				Description:         "Key algorithms supported by the tenant.",
				MarkdownDescription: "Key algorithms supported by the tenant.",
			},
			"supported_key_lengths": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.Int64Type,
				Description:         "Key sizes supported by the tenant.",
				MarkdownDescription: "Key sizes supported by the tenant.",
			},
			"supports_pkcs12_generation": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether server-generated PKCS#12 output is supported.",
				MarkdownDescription: "Whether server-generated PKCS#12 output is supported.",
			},
			"supports_csr_validation_only": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the API supports CSR validation-only mode.",
				MarkdownDescription: "Whether the API supports CSR validation-only mode.",
			},
			"supports_certificate_hold": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether certificates can be placed on hold (instead of immediate revocation).",
				MarkdownDescription: "Whether certificates can be placed on hold (instead of immediate revocation).",
			},
			"supports_recovery": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether recovery/key backup is supported.",
				MarkdownDescription: "Whether recovery/key backup is supported.",
			},
			"api_version": schema.StringAttribute{
				Computed:            true,
				Description:         "Entrust CA Gateway API version reported by the service.",
				MarkdownDescription: "Entrust CA Gateway API version reported by the service.",
			},
		},
	}
}

func (d *DataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	apiClient, ok := req.ProviderData.(*client.APIClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "Provider configuration was not an Entrust API client.")
		return
	}

	d.client = apiClient
}

func (d *DataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	caps, err := d.client.GetCapabilities(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to fetch capabilities", err.Error())
		return
	}

	state, diags := flattenCapabilities(ctx, caps)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

type capabilitiesModel struct {
	ID                       types.String `tfsdk:"id"`
	SupportedSANTypes        types.List   `tfsdk:"supported_san_types"`
	SupportedKeyTypes        types.List   `tfsdk:"supported_key_types"`
	SupportedKeyLengths      types.List   `tfsdk:"supported_key_lengths"`
	SupportsPKCS12Generation types.Bool   `tfsdk:"supports_pkcs12_generation"`
	SupportsCSRValidation    types.Bool   `tfsdk:"supports_csr_validation_only"`
	SupportsCertificateHold  types.Bool   `tfsdk:"supports_certificate_hold"`
	SupportsRecovery         types.Bool   `tfsdk:"supports_recovery"`
	APIVersion               types.String `tfsdk:"api_version"`
}

func flattenCapabilities(ctx context.Context, caps *client.Capabilities) (capabilitiesModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	sanTypes, d := types.ListValueFrom(ctx, types.StringType, caps.SupportedSANTypes)
	diags.Append(d...)

	keyTypes, d := types.ListValueFrom(ctx, types.StringType, caps.SupportedKeyTypes)
	diags.Append(d...)

	keyLengths, d := types.ListValueFrom(ctx, types.Int64Type, intsToInt64(caps.SupportedKeyLengths))
	diags.Append(d...)

	state := capabilitiesModel{
		ID:                       types.StringValue("entrust-cagw-capabilities"),
		SupportedSANTypes:        sanTypes,
		SupportedKeyTypes:        keyTypes,
		SupportedKeyLengths:      keyLengths,
		SupportsPKCS12Generation: types.BoolValue(caps.SupportsPKCS12Generation),
		SupportsCSRValidation:    types.BoolValue(caps.SupportsCSRValidationOnly),
		SupportsCertificateHold:  types.BoolValue(caps.SupportsCertificateHold),
		SupportsRecovery:         types.BoolValue(caps.SupportsRecovery),
		APIVersion:               types.StringValue(caps.APIVersion),
	}

	return state, diags
}

func intsToInt64(values []int) []int64 {
	result := make([]int64, len(values))
	for i, v := range values {
		result[i] = int64(v)
	}
	return result
}
