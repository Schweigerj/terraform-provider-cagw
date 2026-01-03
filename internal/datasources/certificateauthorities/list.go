package certificateauthorities

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

// Ensure implementation satisfies interface.
var _ datasource.DataSource = (*ListDataSource)(nil)

// NewList creates the certificate authorities list data source.
func NewList() datasource.DataSource {
	return &ListDataSource{}
}

// ListDataSource lists Entrust certificate authorities.
type ListDataSource struct {
	client *client.APIClient
}

// Metadata sets the data source type name.
func (d *ListDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate_authorities"
}

// Schema describes the data source schema.
func (d *ListDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves metadata for all certificate authorities visible to the caller.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Identifier for this query (timestamp-based).",
				MarkdownDescription: "Identifier for this query (timestamp-based).",
			},
			"certificate_authorities": schema.ListNestedAttribute{
				Computed:            true,
				Description:         "Certificate authorities returned by the API.",
				MarkdownDescription: "Certificate authorities returned by the API.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							Description:         "Certificate authority identifier.",
							MarkdownDescription: "Certificate authority identifier.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							Description:         "Human-readable CA name.",
							MarkdownDescription: "Human-readable CA name.",
						},
						"status": schema.StringAttribute{
							Computed:            true,
							Description:         "Current CA status.",
							MarkdownDescription: "Current CA status.",
						},
						"description": schema.StringAttribute{
							Computed:            true,
							Description:         "CA description, when available.",
							MarkdownDescription: "CA description, when available.",
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
							Description:         "Creation timestamp returned by Entrust.",
							MarkdownDescription: "Creation timestamp returned by Entrust.",
						},
						"updated_at": schema.StringAttribute{
							Computed:            true,
							Description:         "Last-updated timestamp returned by Entrust.",
							MarkdownDescription: "Last-updated timestamp returned by Entrust.",
						},
					},
				},
			},
		},
	}
}

// Configure attaches the API client.
func (d *ListDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read fetches all certificate authorities.
func (d *ListDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	authorities, err := d.client.ListCertificateAuthorities(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list certificate authorities", err.Error())
		return
	}

	data := certificateAuthoritiesModel{
		ID: types.StringValue(fmt.Sprintf("certificate-authorities-%d", time.Now().UnixNano())),
	}

	for _, ca := range authorities {
		item := certificateAuthorityModel{
			ID:                 types.StringValue(ca.ID),
			Name:               types.StringValue(ca.Name),
			Status:             types.StringValue(ca.Status),
			Description:        types.StringValue(ca.Description),
			EnrollmentEndpoint: types.StringValue(ca.EnrollmentEndpoint),
			CreatedAt:          types.StringValue(ca.CreatedAt),
			UpdatedAt:          types.StringValue(ca.UpdatedAt),
		}

		listValue, diag := types.ListValueFrom(ctx, types.StringType, ca.ProfileIDs)
		resp.Diagnostics.Append(diag...)
		if resp.Diagnostics.HasError() {
			return
		}
		item.ProfileIDs = listValue

		data.CertificateAuthorities = append(data.CertificateAuthorities, item)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

type certificateAuthoritiesModel struct {
	ID                     types.String                `tfsdk:"id"`
	CertificateAuthorities []certificateAuthorityModel `tfsdk:"certificate_authorities"`
}

type certificateAuthorityModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Status             types.String `tfsdk:"status"`
	Description        types.String `tfsdk:"description"`
	ProfileIDs         types.List   `tfsdk:"profile_ids"`
	EnrollmentEndpoint types.String `tfsdk:"enrollment_endpoint"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
}
