package profiles

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

var _ datasource.DataSource = (*DataSource)(nil)

// New returns the single profile data source.
func New() datasource.DataSource {
	return &DataSource{}
}

// DataSource retrieves a specific profile.
type DataSource struct {
	client *client.APIClient
}

func (d *DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_profile"
}

func (d *DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"profile_id": schema.StringAttribute{
			Required:            true,
			Description:         "Identifier of the profile to retrieve.",
			MarkdownDescription: "Identifier of the profile to retrieve.",
		},
	}

	for name, attr := range profileAttributes() {
		switch a := attr.(type) {
		case schema.StringAttribute:
			a.Computed = true
			attrs[name] = a
		case schema.ListAttribute:
			a.Computed = true
			attrs[name] = a
		default:
			attrs[name] = attr
		}
	}

	resp.Schema = schema.Schema{
		Description: "Retrieves metadata for a specific enrollment profile.",
		Attributes:  attrs,
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

func (d *DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	var data profileDataSourceModel

	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := data.ProfileID.ValueString()
	if id == "" {
		resp.Diagnostics.AddError("Missing profile ID", "Provide a value for profile_id.")
		return
	}

	profile, err := d.client.GetProfile(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to fetch profile", err.Error())
		return
	}

	model, diags := newProfileModel(ctx, *profile)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.profileModel = model
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

type profileDataSourceModel struct {
	ProfileID types.String `tfsdk:"profile_id"`
	profileModel
}
