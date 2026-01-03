package profiles

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

var _ datasource.DataSource = (*ListDataSource)(nil)

// NewList returns the profiles list data source.
func NewList() datasource.DataSource {
	return &ListDataSource{}
}

// ListDataSource lists Entrust enrollment profiles.
type ListDataSource struct {
	client *client.APIClient
}

func (d *ListDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_profiles"
}

func (d *ListDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists enrollment profiles available under the configured credentials.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Identifier for this query (timestamp-based).",
				MarkdownDescription: "Identifier for this query (timestamp-based).",
			},
			"profiles": schema.ListNestedAttribute{
				Computed:            true,
				Description:         "Profiles returned by Entrust CA Gateway.",
				MarkdownDescription: "Profiles returned by Entrust CA Gateway.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: profileAttributes(),
				},
			},
		},
	}
}

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

func (d *ListDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	profiles, err := d.client.ListProfiles(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to list profiles", err.Error())
		return
	}

	state := profileListModel{
		ID: types.StringValue(fmt.Sprintf("profiles-%d", time.Now().UnixNano())),
	}

	for _, profile := range profiles {
		model, diags := newProfileModel(ctx, profile)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Profiles = append(state.Profiles, model)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

type profileListModel struct {
	ID       types.String   `tfsdk:"id"`
	Profiles []profileModel `tfsdk:"profiles"`
}

type profileModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Status          types.String `tfsdk:"status"`
	Description     types.String `tfsdk:"description"`
	CertificateType types.String `tfsdk:"certificate_type"`
	Subject         types.String `tfsdk:"subject"`
	KeyTypes        types.List   `tfsdk:"key_types"`
	KeyLengths      types.List   `tfsdk:"key_lengths"`
	SANTypes        types.List   `tfsdk:"san_types"`
	CreatedAt       types.String `tfsdk:"created_at"`
	UpdatedAt       types.String `tfsdk:"updated_at"`
}

func newProfileModel(ctx context.Context, profile client.Profile) (profileModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	keyTypes, d := types.ListValueFrom(ctx, types.StringType, profile.KeyTypes)
	diags.Append(d...)

	keyLengths, d := types.ListValueFrom(ctx, types.Int64Type, intsToInt64(profile.KeyLengths))
	diags.Append(d...)

	sanTypes, d := types.ListValueFrom(ctx, types.StringType, profile.SANTypes)
	diags.Append(d...)

	model := profileModel{
		ID:              types.StringValue(profile.ID),
		Name:            types.StringValue(profile.Name),
		Status:          types.StringValue(profile.Status),
		Description:     types.StringValue(profile.Description),
		CertificateType: types.StringValue(profile.CertificateType),
		Subject:         types.StringValue(profile.Subject),
		KeyTypes:        keyTypes,
		KeyLengths:      keyLengths,
		SANTypes:        sanTypes,
		CreatedAt:       types.StringValue(profile.CreatedAt),
		UpdatedAt:       types.StringValue(profile.UpdatedAt),
	}

	return model, diags
}

func intsToInt64(values []int) []int64 {
	result := make([]int64, len(values))
	for i, v := range values {
		result[i] = int64(v)
	}
	return result
}

func profileAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:            true,
			Description:         "Profile identifier.",
			MarkdownDescription: "Profile identifier.",
		},
		"name": schema.StringAttribute{
			Computed:            true,
			Description:         "Profile name.",
			MarkdownDescription: "Profile name.",
		},
		"status": schema.StringAttribute{
			Computed:            true,
			Description:         "Profile status.",
			MarkdownDescription: "Profile status.",
		},
		"description": schema.StringAttribute{
			Computed:            true,
			Description:         "Profile description.",
			MarkdownDescription: "Profile description.",
		},
		"certificate_type": schema.StringAttribute{
			Computed:            true,
			Description:         "Certificate type issued by this profile.",
			MarkdownDescription: "Certificate type issued by this profile.",
		},
		"subject": schema.StringAttribute{
			Computed:            true,
			Description:         "Subject template information.",
			MarkdownDescription: "Subject template information.",
		},
		"key_types": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			Description:         "Supported key types.",
			MarkdownDescription: "Supported key types.",
		},
		"key_lengths": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.Int64Type,
			Description:         "Supported key lengths.",
			MarkdownDescription: "Supported key lengths.",
		},
		"san_types": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			Description:         "Supported SAN types.",
			MarkdownDescription: "Supported SAN types.",
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
	}
}
