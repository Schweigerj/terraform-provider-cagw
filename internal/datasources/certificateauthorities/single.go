package certificateauthorities

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

var _ datasource.DataSource = (*AuthorityDataSource)(nil)

// NewAuthority returns the single certificate authority data source.
func NewAuthority() datasource.DataSource {
	return &AuthorityDataSource{}
}

// AuthorityDataSource fetches a single CA by ID.
type AuthorityDataSource struct {
	client *client.APIClient
}

func (d *AuthorityDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate_authority"
}

func (d *AuthorityDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves metadata for a specific certificate authority.",
		Attributes: map[string]schema.Attribute{
			"certificate_authority_id": schema.StringAttribute{
				Required:            true,
				Description:         "Identifier of the certificate authority to retrieve.",
				MarkdownDescription: "Identifier of the certificate authority to retrieve.",
			},
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Echoes the certificate authority ID for Terraform state tracking.",
				MarkdownDescription: "Echoes the certificate authority ID for Terraform state tracking.",
			},
			"name": schema.StringAttribute{
				Computed:            true,
				Description:         "CA name.",
				MarkdownDescription: "CA name.",
			},
			"status": schema.StringAttribute{
				Computed:            true,
				Description:         "CA status.",
				MarkdownDescription: "CA status.",
			},
			"description": schema.StringAttribute{
				Computed:            true,
				Description:         "CA description.",
				MarkdownDescription: "CA description.",
			},
			"profile_ids": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				Description:         "Profile identifiers available under this CA.",
				MarkdownDescription: "Profile identifiers available under this CA.",
			},
			"enrollment_endpoint": schema.StringAttribute{
				Computed:            true,
				Description:         "Enrollment endpoint for issuing certificates under this CA.",
				MarkdownDescription: "Enrollment endpoint for issuing certificates under this CA.",
			},
			"created_at": schema.StringAttribute{
				Computed:            true,
				Description:         "Creation timestamp reported by Entrust.",
				MarkdownDescription: "Creation timestamp reported by Entrust.",
			},
			"updated_at": schema.StringAttribute{
				Computed:            true,
				Description:         "Last update timestamp reported by Entrust.",
				MarkdownDescription: "Last update timestamp reported by Entrust.",
			},
		},
	}
}

func (d *AuthorityDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *AuthorityDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	var data authorityModel
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	caID := data.CertificateAuthorityID.ValueString()
	if caID == "" {
		resp.Diagnostics.AddError("Missing certificate authority ID", "Provide a value for certificate_authority_id.")
		return
	}

	ca, err := d.client.GetCertificateAuthority(ctx, caID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to fetch certificate authority", err.Error())
		return
	}

	profiles, diag := types.ListValueFrom(ctx, types.StringType, ca.ProfileIDs)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.ID = types.StringValue(ca.ID)
	data.Name = types.StringValue(ca.Name)
	data.Status = types.StringValue(ca.Status)
	data.Description = types.StringValue(ca.Description)
	data.ProfileIDs = profiles
	data.EnrollmentEndpoint = types.StringValue(ca.EnrollmentEndpoint)
	data.CreatedAt = types.StringValue(ca.CreatedAt)
	data.UpdatedAt = types.StringValue(ca.UpdatedAt)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

type authorityModel struct {
	CertificateAuthorityID types.String `tfsdk:"certificate_authority_id"`
	ID                     types.String `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	Status                 types.String `tfsdk:"status"`
	Description            types.String `tfsdk:"description"`
	ProfileIDs             types.List   `tfsdk:"profile_ids"`
	EnrollmentEndpoint     types.String `tfsdk:"enrollment_endpoint"`
	CreatedAt              types.String `tfsdk:"created_at"`
	UpdatedAt              types.String `tfsdk:"updated_at"`
}
