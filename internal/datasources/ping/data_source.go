package ping

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

var _ datasource.DataSource = (*DataSource)(nil)

// New returns a ping data source instance.
func New() datasource.DataSource {
	return &DataSource{}
}

// DataSource implements the ping data source.
type DataSource struct {
	client *client.APIClient
}

// Metadata describes the data source.
func (d *DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ping"
}

// Schema defines the ping data source attributes.
func (d *DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Performs a health check against the Entrust CA Gateway `/v1/ping` endpoint.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Unique identifier for this ping invocation.",
				MarkdownDescription: "Unique identifier for this ping invocation (uses the request correlation ID).",
			},
			"status_code": schema.Int64Attribute{
				Computed:            true,
				Description:         "HTTP status code returned by the ping endpoint.",
				MarkdownDescription: "HTTP status code returned by the ping endpoint.",
			},
			"response_body": schema.StringAttribute{
				Computed:            true,
				Description:         "Raw response body from the ping endpoint.",
				MarkdownDescription: "Raw response body from the ping endpoint.",
			},
			"endpoint": schema.StringAttribute{
				Computed:            true,
				Description:         "The fully-qualified URL that was called.",
				MarkdownDescription: "The fully-qualified URL that was called.",
			},
			"correlation_id": schema.StringAttribute{
				Computed:            true,
				Description:         "Correlation ID attached to the request.",
				MarkdownDescription: "Correlation ID attached to the request.",
			},
			"latency_ms": schema.Int64Attribute{
				Computed:            true,
				Description:         "Request latency in milliseconds.",
				MarkdownDescription: "Request latency in milliseconds.",
			},
		},
	}
}

// Configure injects the provider client.
func (d *DataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	apiClient, ok := req.ProviderData.(*client.APIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data",
			"Unable to configure the ping data source because the provider data was not an API client.",
		)
		return
	}

	d.client = apiClient
}

// Read executes the ping request.
func (d *DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError(
			"Provider not configured",
			"The Entrust provider client was not initialized.",
		)
		return
	}

	var data pingModel
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	result, err := d.client.Ping(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Ping request failed", err.Error())
		return
	}

	data.ID = types.StringValue(result.CorrelationID)
	data.StatusCode = types.Int64Value(int64(result.StatusCode))
	data.ResponseBody = types.StringValue(result.ResponseBody)
	data.Endpoint = types.StringValue(result.Endpoint)
	data.CorrelationID = types.StringValue(result.CorrelationID)
	data.LatencyMs = types.Int64Value(result.RequestLatency.Milliseconds())

	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}

type pingModel struct {
	ID            types.String `tfsdk:"id"`
	StatusCode    types.Int64  `tfsdk:"status_code"`
	ResponseBody  types.String `tfsdk:"response_body"`
	Endpoint      types.String `tfsdk:"endpoint"`
	CorrelationID types.String `tfsdk:"correlation_id"`
	LatencyMs     types.Int64  `tfsdk:"latency_ms"`
}
