package certificates

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

var _ datasource.DataSource = (*DataSource)(nil)

// New returns the certificate lookup data source.
func New() datasource.DataSource {
	return &DataSource{}
}

// DataSource retrieves a certificate by serial number.
type DataSource struct {
	client *client.APIClient
}

func (d *DataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (d *DataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up a certificate by serial number.",
		Attributes: map[string]schema.Attribute{
			"serial_number": schema.StringAttribute{
				Required:            true,
				Description:         "Serial number of the certificate to fetch.",
				MarkdownDescription: "Serial number of the certificate to fetch.",
			},
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform identifier, mirrors the serial number.",
				MarkdownDescription: "Terraform identifier, mirrors the serial number.",
			},
			"certificate_authority_id": schema.StringAttribute{
				Computed:            true,
				Description:         "Certificate authority that issued the certificate.",
				MarkdownDescription: "Certificate authority that issued the certificate.",
			},
			"profile_id": schema.StringAttribute{
				Computed:            true,
				Description:         "Profile used for issuance.",
				MarkdownDescription: "Profile used for issuance.",
			},
			"status": schema.StringAttribute{
				Computed:            true,
				Description:         "Certificate status (issued, revoked, expired, etc.).",
				MarkdownDescription: "Certificate status (issued, revoked, expired, etc.).",
			},
			"subject_dn": schema.StringAttribute{
				Computed:            true,
				Description:         "Subject distinguished name.",
				MarkdownDescription: "Subject distinguished name.",
			},
			"issuer_dn": schema.StringAttribute{
				Computed:            true,
				Description:         "Issuer distinguished name.",
				MarkdownDescription: "Issuer distinguished name.",
			},
			"subject_alternative_names": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				Description:         "Subject alternative names on the certificate.",
				MarkdownDescription: "Subject alternative names on the certificate.",
			},
			"not_before": schema.StringAttribute{
				Computed:            true,
				Description:         "Not before timestamp.",
				MarkdownDescription: "Not before timestamp.",
			},
			"not_after": schema.StringAttribute{
				Computed:            true,
				Description:         "Not after timestamp.",
				MarkdownDescription: "Not after timestamp.",
			},
			"certificate_pem": schema.StringAttribute{
				Computed:            true,
				Description:         "Certificate PEM output.",
				MarkdownDescription: "Certificate PEM output.",
			},
			"certificate_chain_pem": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				Description:         "Issuer chain in PEM format.",
				MarkdownDescription: "Issuer chain in PEM format.",
			},
			"revocation_reason": schema.StringAttribute{
				Computed:            true,
				Description:         "Revocation reason, if applicable.",
				MarkdownDescription: "Revocation reason, if applicable.",
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

	var data certificateModel
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	serial := data.SerialNumber.ValueString()
	if serial == "" {
		resp.Diagnostics.AddError("Missing serial number", "Provide a value for serial_number.")
		return
	}

	cert, err := d.client.GetCertificate(ctx, serial)
	if err != nil {
		resp.Diagnostics.AddError("Unable to fetch certificate", err.Error())
		return
	}

	model, diags := flattenCertificate(ctx, cert)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type certificateModel struct {
	SerialNumber            types.String `tfsdk:"serial_number"`
	ID                      types.String `tfsdk:"id"`
	CertificateAuthorityID  types.String `tfsdk:"certificate_authority_id"`
	ProfileID               types.String `tfsdk:"profile_id"`
	Status                  types.String `tfsdk:"status"`
	SubjectDN               types.String `tfsdk:"subject_dn"`
	IssuerDN                types.String `tfsdk:"issuer_dn"`
	SubjectAlternativeNames types.List   `tfsdk:"subject_alternative_names"`
	NotBefore               types.String `tfsdk:"not_before"`
	NotAfter                types.String `tfsdk:"not_after"`
	CertificatePEM          types.String `tfsdk:"certificate_pem"`
	CertificateChainPEM     types.List   `tfsdk:"certificate_chain_pem"`
	RevocationReason        types.String `tfsdk:"revocation_reason"`
	CreatedAt               types.String `tfsdk:"created_at"`
	UpdatedAt               types.String `tfsdk:"updated_at"`
}

func flattenCertificate(ctx context.Context, cert *client.Certificate) (certificateModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	sanList, d := types.ListValueFrom(ctx, types.StringType, cert.SubjectAlternativeNames)
	diags.Append(d...)

	chainList, d := types.ListValueFrom(ctx, types.StringType, cert.CertificateChainPEM)
	diags.Append(d...)

	model := certificateModel{
		SerialNumber:            types.StringValue(cert.SerialNumber),
		ID:                      types.StringValue(cert.SerialNumber),
		CertificateAuthorityID:  types.StringValue(cert.CertificateAuthorityID),
		ProfileID:               types.StringValue(cert.ProfileID),
		Status:                  types.StringValue(cert.Status),
		SubjectDN:               types.StringValue(cert.SubjectDN),
		IssuerDN:                types.StringValue(cert.IssuerDN),
		SubjectAlternativeNames: sanList,
		NotBefore:               types.StringValue(cert.NotBefore),
		NotAfter:                types.StringValue(cert.NotAfter),
		CertificatePEM:          types.StringValue(cert.CertificatePEM),
		CertificateChainPEM:     chainList,
		RevocationReason:        types.StringValue(cert.RevocationReason),
		CreatedAt:               types.StringValue(cert.CreatedAt),
		UpdatedAt:               types.StringValue(cert.UpdatedAt),
	}

	return model, diags
}
