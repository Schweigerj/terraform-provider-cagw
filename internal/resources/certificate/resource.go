package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

var (
	_ resource.Resource                   = (*Resource)(nil)
	_ resource.ResourceWithImportState    = (*Resource)(nil)
	_ resource.ResourceWithValidateConfig = (*Resource)(nil)
	_ resource.ResourceWithModifyPlan     = (*Resource)(nil)
)

var (
	defaultRevocationReason = "unspecified"
	revocationReasonValues  = map[string]string{
		"unspecified":          "unspecified",
		"keycompromise":        "keyCompromise",
		"cacompromise":         "caCompromise",
		"affiliationchanged":   "affiliationChanged",
		"superseded":           "superseded",
		"cessationofoperation": "cessationOfOperation",
		"certificatehold":      "certificateHold",
		"removefromcrl":        "removeFromCRL",
		"privilegewithdrawn":   "privilegeWithdrawn",
		"aacompromise":         "aACompromise",
	}
	revocationReasonDisplay = []string{
		"unspecified",
		"keyCompromise",
		"caCompromise",
		"affiliationChanged",
		"superseded",
		"cessationOfOperation",
		"certificateHold",
		"removeFromCRL",
		"privilegeWithdrawn",
		"aACompromise",
	}
)

// New returns a new certificate resource.
func New() resource.Resource {
	return &Resource{}
}

// Resource implements the entrust_cagw_certificate Terraform resource.
type Resource struct {
	client            *client.APIClient
	fetchCapabilities func(context.Context) (*client.Capabilities, error)
	fetchProfile      func(context.Context, string) (*client.Profile, error)
	cacheMu           sync.Mutex
	capabilitiesCache *client.Capabilities
	profileCache      map[string]*client.Profile
}

func (r *Resource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *Resource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Issues and manages Entrust CA Gateway certificates via CSR enrollment and revoke-on-destroy semantics.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				Description:         "Terraform resource identifier (certificate serial number).",
				MarkdownDescription: "Terraform resource identifier (certificate serial number).",
			},
			"certificate_authority_id": schema.StringAttribute{
				Required:            true,
				Description:         "Certificate authority identifier used for enrollment.",
				MarkdownDescription: "Certificate authority identifier used for enrollment.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"profile_id": schema.StringAttribute{
				Required:            true,
				Description:         "Profile identifier used for enrollment.",
				MarkdownDescription: "Profile identifier used for enrollment.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"csr_pem": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				Description:         "PEM-encoded certificate signing request.",
				MarkdownDescription: "PEM-encoded certificate signing request.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"csr_key_type": schema.StringAttribute{
				Optional:            true,
				Description:         "Key algorithm used in the CSR (helps validate profile compatibility).",
				MarkdownDescription: "Key algorithm used in the CSR (helps validate profile compatibility).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"csr_key_length": schema.Int64Attribute{
				Optional:            true,
				Description:         "Key length used in the CSR (helps validate profile compatibility).",
				MarkdownDescription: "Key length used in the CSR (helps validate profile compatibility).",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"subject_alternative_names": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				Description:         "Subject Alternative Names requested for the certificate.",
				MarkdownDescription: "Subject Alternative Names requested for the certificate.",
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
					listplanmodifier.UseStateForUnknown(),
				},
			},
			"revocation_reason": schema.StringAttribute{
				Optional:            true,
				Description:         "Reason to use when revoking the certificate on destroy (e.g., `keyCompromise`, `superseded`).",
				MarkdownDescription: "Reason to use when revoking the certificate on destroy (e.g., `keyCompromise`, `superseded`).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"revoke_on_destroy": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				Description:         "Set to false to skip automatic revocation on destroy.",
				MarkdownDescription: "Set to false to skip automatic revocation on destroy.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"hold_on_destroy": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				Description:         "Set to true to request a certificate hold (if supported) instead of revocation on destroy.",
				MarkdownDescription: "Set to true to request a certificate hold (if supported) instead of revocation on destroy.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"rotate_before_days": schema.Int64Attribute{
				Optional:            true,
				Description:         "Number of days before expiration to proactively rotate (forces replacement when within threshold).",
				MarkdownDescription: "Number of days before expiration to proactively rotate (forces replacement when within threshold).",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"generate_pkcs12": schema.BoolAttribute{
				Optional:            true,
				Description:         "Set to true to request server-generated PKCS#12 output in addition to the PEM certificate (opt-in).",
				MarkdownDescription: "Set to true to request server-generated PKCS#12 output in addition to the PEM certificate (opt-in).",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.RequiresReplace(),
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"pkcs12_passphrase": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				Description:         "Passphrase required when generate_pkcs12 is true.",
				MarkdownDescription: "Passphrase required when `generate_pkcs12` is true.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"serial_number": schema.StringAttribute{
				Computed:            true,
				Description:         "Issued certificate serial number.",
				MarkdownDescription: "Issued certificate serial number.",
			},
			"status": schema.StringAttribute{
				Computed:            true,
				Description:         "Certificate status reported by Entrust.",
				MarkdownDescription: "Certificate status reported by Entrust.",
			},
			"subject_dn": schema.StringAttribute{
				Computed:            true,
				Description:         "Subject distinguished name returned by Entrust.",
				MarkdownDescription: "Subject distinguished name returned by Entrust.",
			},
			"issuer_dn": schema.StringAttribute{
				Computed:            true,
				Description:         "Issuer distinguished name returned by Entrust.",
				MarkdownDescription: "Issuer distinguished name returned by Entrust.",
			},
			"not_before": schema.StringAttribute{
				Computed:            true,
				Description:         "Not-before timestamp.",
				MarkdownDescription: "Not-before timestamp.",
			},
			"not_after": schema.StringAttribute{
				Computed:            true,
				Description:         "Not-after timestamp.",
				MarkdownDescription: "Not-after timestamp.",
			},
			"certificate_pem": schema.StringAttribute{
				Computed:            true,
				Description:         "PEM-encoded certificate body.",
				MarkdownDescription: "PEM-encoded certificate body.",
			},
			"certificate_chain_pem": schema.ListAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				Description:         "PEM-encoded issuer chain.",
				MarkdownDescription: "PEM-encoded issuer chain.",
			},
			"certificate_fingerprint_sha1": schema.StringAttribute{
				Computed:            true,
				Description:         "SHA-1 fingerprint of the issued certificate.",
				MarkdownDescription: "SHA-1 fingerprint of the issued certificate.",
			},
			"certificate_fingerprint_sha256": schema.StringAttribute{
				Computed:            true,
				Description:         "SHA-256 fingerprint of the issued certificate.",
				MarkdownDescription: "SHA-256 fingerprint of the issued certificate.",
			},
			"pkcs12_base64": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				Description:         "Base64-encoded PKCS#12 blob returned by Entrust when `generate_pkcs12` is enabled. This is sensitive state and should be handled carefully.",
				MarkdownDescription: "Base64-encoded PKCS#12 blob returned by Entrust when `generate_pkcs12` is enabled. This is sensitive state and should be handled carefully.",
			},
			"revocation_status_reason": schema.StringAttribute{
				Computed:            true,
				Description:         "Revocation reason reported by Entrust.",
				MarkdownDescription: "Revocation reason reported by Entrust.",
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

func (r *Resource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	apiClient, ok := req.ProviderData.(*client.APIClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "Provider configuration was not an Entrust API client.")
		return
	}

	r.client = apiClient
	r.capabilitiesCache = nil
	r.profileCache = map[string]*client.Profile{}
	r.fetchCapabilities = r.cachedCapabilities
	r.fetchProfile = r.cachedProfile
}

func (r *Resource) cachedCapabilities(ctx context.Context) (*client.Capabilities, error) {
	r.cacheMu.Lock()
	cached := r.capabilitiesCache
	r.cacheMu.Unlock()
	if cached != nil {
		return cached, nil
	}

	if r.client == nil {
		return nil, fmt.Errorf("client not configured")
	}

	caps, err := r.client.GetCapabilities(ctx)
	if err != nil {
		return nil, err
	}

	r.cacheMu.Lock()
	r.capabilitiesCache = caps
	r.cacheMu.Unlock()

	return caps, nil
}

func (r *Resource) cachedProfile(ctx context.Context, id string) (*client.Profile, error) {
	key := strings.TrimSpace(id)
	if key == "" {
		return nil, fmt.Errorf("profile id is required")
	}

	r.cacheMu.Lock()
	if r.profileCache != nil {
		if profile, ok := r.profileCache[key]; ok {
			r.cacheMu.Unlock()
			return profile, nil
		}
	}
	r.cacheMu.Unlock()

	if r.client == nil {
		return nil, fmt.Errorf("client not configured")
	}

	profile, err := r.client.GetProfile(ctx, key)
	if err != nil {
		return nil, err
	}

	r.cacheMu.Lock()
	if r.profileCache == nil {
		r.profileCache = map[string]*client.Profile{}
	}
	r.profileCache[key] = profile
	r.cacheMu.Unlock()

	return profile, nil
}

func (r *Resource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if r.fetchCapabilities == nil {
		return
	}

	var config resourceModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.RotateBeforeDays.IsNull() && !config.RotateBeforeDays.IsUnknown() {
		if config.RotateBeforeDays.ValueInt64() <= 0 {
			resp.Diagnostics.AddAttributeError(
				path.Root("rotate_before_days"),
				"Invalid rotation threshold",
				"`rotate_before_days` must be greater than zero when set.",
			)
			return
		}
	}

	caps, err := r.fetchCapabilities(ctx)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Unable to fetch capabilities",
			fmt.Sprintf("The provider could not retrieve capabilities for plan-time validation: %v", err),
		)
		return
	}

	if caps != nil && !caps.SupportsPKCS12Generation && config.GeneratePKCS12.ValueBool() {
		resp.Diagnostics.AddAttributeError(
			path.Root("generate_pkcs12"),
			"PKCS#12 generation not supported",
			"The Entrust tenant does not support server-generated PKCS#12 bundles. Disable `generate_pkcs12` or enable the capability in Entrust.",
		)
	}

	var profile *client.Profile
	if r.fetchProfile != nil && !config.ProfileID.IsNull() && !config.ProfileID.IsUnknown() {
		p, err := r.fetchProfile(ctx, config.ProfileID.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("profile_id"),
				"Unable to load profile",
				fmt.Sprintf("Failed to retrieve profile details for %q: %v", config.ProfileID.ValueString(), err),
			)
			return
		}
		profile = p
	}

	resp.Diagnostics.Append(validateLifecycleOptions(config, caps)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parsedCSR, diags := parseCSRAttributes(config.CSRPEM)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	sanList := config.SubjectAlternativeNames
	if (sanList.IsNull() || sanList.IsUnknown()) && parsedCSR != nil && len(parsedCSR.SANs) > 0 {
		sanList, diags = types.ListValueFrom(ctx, types.StringType, parsedCSR.SANs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(validateSubjectAlternativeNames(ctx, caps, profile, sanList)...)
	resp.Diagnostics.Append(validateKeyRequirements(profile, parsedCSR, config.CSRKeyType, config.CSRKeyLength)...)
}

func (r *Resource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.Plan.Raw.IsUnknown() {
		return
	}

	var plan resourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.RotateBeforeDays.IsNull() || plan.RotateBeforeDays.IsUnknown() {
		return
	}

	rotateDays := plan.RotateBeforeDays.ValueInt64()
	if rotateDays <= 0 {
		return
	}

	if req.State.Raw.IsNull() || req.State.Raw.IsUnknown() {
		return
	}

	var state resourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	notAfter := strings.TrimSpace(state.NotAfter.ValueString())
	if notAfter == "" {
		return
	}

	expiryTime, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"Unable to parse not_after",
			fmt.Sprintf("Failed to parse not_after timestamp %q: %v", notAfter, err),
		)
		return
	}

	cutoff := time.Now().UTC().Add(time.Duration(rotateDays) * 24 * time.Hour)
	if !expiryTime.After(cutoff) {
		resp.RequiresReplace(path.Root("serial_number"))
	}
}

func (r *Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	var plan resourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	revokeOnDestroy := boolValue(plan.RevokeOnDestroy, true)
	holdOnDestroy := boolValue(plan.HoldOnDestroy, false)

	var normalizedReason string
	if !plan.RevocationReason.IsNull() && !plan.RevocationReason.IsUnknown() {
		value := strings.TrimSpace(plan.RevocationReason.ValueString())
		if value != "" {
			norm, ok := normalizeRevocationReasonString(value)
			if !ok {
				resp.Diagnostics.AddAttributeError(
					path.Root("revocation_reason"),
					"Unsupported revocation reason",
					fmt.Sprintf("Valid values are: %s.", strings.Join(revocationReasonDisplay, ", ")),
				)
				return
			}
			normalizedReason = norm
		}
	}

	var generatePKCS12 bool
	if !plan.GeneratePKCS12.IsNull() && !plan.GeneratePKCS12.IsUnknown() {
		generatePKCS12 = plan.GeneratePKCS12.ValueBool()
	}

	var passphrase string
	passphraseSet := false
	if !plan.PKCS12Passphrase.IsNull() && !plan.PKCS12Passphrase.IsUnknown() {
		passphrase = strings.TrimSpace(plan.PKCS12Passphrase.ValueString())
		passphraseSet = passphrase != ""
	}

	if generatePKCS12 && !passphraseSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("pkcs12_passphrase"),
			"Missing PKCS#12 passphrase",
			"A passphrase must be supplied when `generate_pkcs12` is set to true.",
		)
		return
	}
	if !generatePKCS12 && passphraseSet {
		resp.Diagnostics.AddAttributeError(
			path.Root("pkcs12_passphrase"),
			"Passphrase provided without PKCS#12 generation",
			"Set `generate_pkcs12 = true` when providing a PKCS#12 passphrase or remove the passphrase.",
		)
		return
	}

	sans, diags := expandStringList(ctx, plan.SubjectAlternativeNames)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	enrollmentReq := client.CertificateEnrollmentRequest{
		ProfileID:               plan.ProfileID.ValueString(),
		CSR:                     plan.CSRPEM.ValueString(),
		SubjectAlternativeNames: sans,
	}
	if generatePKCS12 {
		enrollmentReq.GeneratePKCS12 = true
		enrollmentReq.PKCS12Passphrase = passphrase
	}

	cert, err := r.client.EnrollCertificate(ctx, plan.CertificateAuthorityID.ValueString(), enrollmentReq)
	if err != nil {
		resp.Diagnostics.AddError("Certificate enrollment failed", err.Error())
		return
	}

	state, diags := flattenCertificate(ctx, cert)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.CertificateAuthorityID = plan.CertificateAuthorityID
	state.ProfileID = plan.ProfileID
	state.CSRKeyType = plan.CSRKeyType
	state.CSRKeyLength = plan.CSRKeyLength
	if normalizedReason != "" {
		state.RevocationReason = types.StringValue(normalizedReason)
	} else {
		state.RevocationReason = types.StringNull()
	}
	state.RevokeOnDestroy = types.BoolValue(revokeOnDestroy)
	state.HoldOnDestroy = types.BoolValue(holdOnDestroy)
	state.RotateBeforeDays = plan.RotateBeforeDays
	state.GeneratePKCS12 = types.BoolValue(generatePKCS12)
	if passphraseSet {
		state.PKCS12Passphrase = types.StringValue(passphrase)
	} else {
		state.PKCS12Passphrase = types.StringNull()
	}
	state.CSRPEM = types.StringNull()
	state.ID = state.SerialNumber

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	var state resourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	serial := state.SerialNumber.ValueString()
	if serial == "" {
		resp.Diagnostics.AddError("Missing serial number", "State is missing the certificate serial number.")
		return
	}

	cert, err := r.client.GetCertificate(ctx, serial)
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}

		resp.Diagnostics.AddError("Unable to refresh certificate", err.Error())
		return
	}

	newState, diags := flattenCertificate(ctx, cert)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	newState.CertificateAuthorityID = state.CertificateAuthorityID
	newState.ProfileID = state.ProfileID
	newState.CSRKeyType = state.CSRKeyType
	newState.CSRKeyLength = state.CSRKeyLength
	newState.RevocationReason = state.RevocationReason
	newState.RevokeOnDestroy = state.RevokeOnDestroy
	newState.HoldOnDestroy = state.HoldOnDestroy
	newState.RotateBeforeDays = state.RotateBeforeDays
	newState.GeneratePKCS12 = state.GeneratePKCS12
	newState.PKCS12Passphrase = state.PKCS12Passphrase
	newState.CSRPEM = types.StringNull()
	newState.ID = newState.SerialNumber

	resp.Diagnostics.Append(resp.State.Set(ctx, &newState)...)
}

func (r *Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Changes require creating a replacement certificate.")
}

func (r *Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Entrust provider must be configured before use.")
		return
	}

	var state resourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	serial := state.SerialNumber.ValueString()
	if serial == "" {
		resp.Diagnostics.AddWarning("Missing serial number", "State did not contain a serial number; skipping revoke.")
		return
	}

	revoke := boolValue(state.RevokeOnDestroy, true)
	if !revoke {
		return
	}

	hold := boolValue(state.HoldOnDestroy, false)
	reason := defaultRevocationReason
	if !state.RevocationReason.IsNull() && !state.RevocationReason.IsUnknown() {
		if value := strings.TrimSpace(state.RevocationReason.ValueString()); value != "" {
			reason = value
		}
	}

	var err error
	if hold {
		err = r.client.HoldCertificate(ctx, serial)
	} else {
		err = r.client.RevokeCertificate(ctx, serial, reason)
	}

	if err != nil && !client.IsNotFound(err) {
		action := "Certificate revocation failed"
		if hold {
			action = "Certificate hold failed"
		}
		resp.Diagnostics.AddError(action, err.Error())
	}
}

func (r *Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("serial_number"), req, resp)
}

type resourceModel struct {
	ID                      types.String `tfsdk:"id"`
	CertificateAuthorityID  types.String `tfsdk:"certificate_authority_id"`
	ProfileID               types.String `tfsdk:"profile_id"`
	CSRPEM                  types.String `tfsdk:"csr_pem"`
	CSRKeyType              types.String `tfsdk:"csr_key_type"`
	CSRKeyLength            types.Int64  `tfsdk:"csr_key_length"`
	SubjectAlternativeNames types.List   `tfsdk:"subject_alternative_names"`
	RevocationReason        types.String `tfsdk:"revocation_reason"`
	RevokeOnDestroy         types.Bool   `tfsdk:"revoke_on_destroy"`
	HoldOnDestroy           types.Bool   `tfsdk:"hold_on_destroy"`
	RotateBeforeDays        types.Int64  `tfsdk:"rotate_before_days"`
	GeneratePKCS12          types.Bool   `tfsdk:"generate_pkcs12"`
	PKCS12Passphrase        types.String `tfsdk:"pkcs12_passphrase"`

	SerialNumber                 types.String `tfsdk:"serial_number"`
	Status                       types.String `tfsdk:"status"`
	SubjectDN                    types.String `tfsdk:"subject_dn"`
	IssuerDN                     types.String `tfsdk:"issuer_dn"`
	NotBefore                    types.String `tfsdk:"not_before"`
	NotAfter                     types.String `tfsdk:"not_after"`
	CertificatePEM               types.String `tfsdk:"certificate_pem"`
	CertificateChainPEM          types.List   `tfsdk:"certificate_chain_pem"`
	CertificateFingerprintSHA1   types.String `tfsdk:"certificate_fingerprint_sha1"`
	CertificateFingerprintSHA256 types.String `tfsdk:"certificate_fingerprint_sha256"`
	PKCS12Base64                 types.String `tfsdk:"pkcs12_base64"`
	RevocationStatusReason       types.String `tfsdk:"revocation_status_reason"`
	CreatedAt                    types.String `tfsdk:"created_at"`
	UpdatedAt                    types.String `tfsdk:"updated_at"`
}

func expandStringList(ctx context.Context, list types.List) ([]string, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return nil, nil
	}

	var values []string
	diags := list.ElementsAs(ctx, &values, false)
	return values, diags
}

func flattenCertificate(ctx context.Context, cert *client.Certificate) (resourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics

	sanList, d := types.ListValueFrom(ctx, types.StringType, cert.SubjectAlternativeNames)
	diags.Append(d...)

	chainList, d := types.ListValueFrom(ctx, types.StringType, cert.CertificateChainPEM)
	diags.Append(d...)

	pkcs12 := types.StringNull()
	if cert.PKCS12 != "" {
		pkcs12 = types.StringValue(cert.PKCS12)
	}

	fpSHA1, fpSHA256, fd := computeFingerprints(cert.CertificatePEM)
	diags.Append(fd...)

	caID := types.StringNull()
	if cert.CertificateAuthorityID != "" {
		caID = types.StringValue(cert.CertificateAuthorityID)
	}

	profileID := types.StringNull()
	if cert.ProfileID != "" {
		profileID = types.StringValue(cert.ProfileID)
	}

	state := resourceModel{
		CertificateAuthorityID:       caID,
		ProfileID:                    profileID,
		SerialNumber:                 types.StringValue(cert.SerialNumber),
		Status:                       types.StringValue(cert.Status),
		SubjectDN:                    types.StringValue(cert.SubjectDN),
		IssuerDN:                     types.StringValue(cert.IssuerDN),
		SubjectAlternativeNames:      sanList,
		NotBefore:                    types.StringValue(cert.NotBefore),
		NotAfter:                     types.StringValue(cert.NotAfter),
		CertificatePEM:               types.StringValue(cert.CertificatePEM),
		CertificateChainPEM:          chainList,
		CertificateFingerprintSHA1:   fpSHA1,
		CertificateFingerprintSHA256: fpSHA256,
		PKCS12Base64:                 pkcs12,
		RevocationStatusReason:       types.StringValue(cert.RevocationReason),
		CreatedAt:                    types.StringValue(cert.CreatedAt),
		UpdatedAt:                    types.StringValue(cert.UpdatedAt),
		GeneratePKCS12:               types.BoolNull(),
		PKCS12Passphrase:             types.StringNull(),
		RevokeOnDestroy:              types.BoolNull(),
		HoldOnDestroy:                types.BoolNull(),
		RotateBeforeDays:             types.Int64Null(),
		RevocationReason:             types.StringNull(),
	}

	return state, diags
}

func computeFingerprints(certPEM string) (types.String, types.String, diag.Diagnostics) {
	var diags diag.Diagnostics

	value := strings.TrimSpace(certPEM)
	if value == "" {
		return types.StringNull(), types.StringNull(), diags
	}

	block, _ := pem.Decode([]byte(value))
	if block == nil {
		diags.AddWarning(
			"Unable to compute certificate fingerprints",
			"Entrust returned a certificate payload that was not valid PEM; fingerprints are unavailable.",
		)
		return types.StringNull(), types.StringNull(), diags
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		diags.AddWarning(
			"Unable to compute certificate fingerprints",
			fmt.Sprintf("Failed to parse certificate for fingerprinting: %v", err),
		)
		return types.StringNull(), types.StringNull(), diags
	}

	sha1Sum := sha1.Sum(cert.Raw)
	sha256Sum := sha256.Sum256(cert.Raw)

	sha1Hex := strings.ToUpper(hex.EncodeToString(sha1Sum[:]))
	sha256Hex := strings.ToUpper(hex.EncodeToString(sha256Sum[:]))

	return types.StringValue(sha1Hex), types.StringValue(sha256Hex), diags
}

func validateLifecycleOptions(config resourceModel, caps *client.Capabilities) diag.Diagnostics {
	var diags diag.Diagnostics

	revoke := boolValue(config.RevokeOnDestroy, true)
	hold := boolValue(config.HoldOnDestroy, false)

	reasonSet := false
	if !config.RevocationReason.IsNull() && !config.RevocationReason.IsUnknown() {
		raw := strings.TrimSpace(config.RevocationReason.ValueString())
		if raw == "" {
			diags.AddAttributeError(
				path.Root("revocation_reason"),
				"Invalid revocation reason",
				"Provide a non-empty value or remove the attribute.",
			)
			return diags
		}

		_, ok := normalizeRevocationReasonString(raw)
		if !ok {
			diags.AddAttributeError(
				path.Root("revocation_reason"),
				"Unsupported revocation reason",
				fmt.Sprintf("Valid values are: %s.", strings.Join(revocationReasonDisplay, ", ")),
			)
			return diags
		}

		reasonSet = true
	}

	if hold && !revoke {
		diags.AddAttributeError(
			path.Root("hold_on_destroy"),
			"Invalid hold configuration",
			"`hold_on_destroy` requires `revoke_on_destroy` to remain true.",
		)
		return diags
	}

	if hold {
		if caps != nil && !caps.SupportsCertificateHold {
			diags.AddAttributeError(
				path.Root("hold_on_destroy"),
				"Certificate hold unsupported",
				"The Entrust tenant does not advertise certificate hold support; disable `hold_on_destroy` or enable the capability.",
			)
		}
		if reasonSet {
			diags.AddAttributeWarning(
				path.Root("revocation_reason"),
				"Revocation reason ignored",
				"`revocation_reason` is ignored when `hold_on_destroy` is true.",
			)
		}
		return diags
	}

	if !revoke && reasonSet {
		diags.AddAttributeWarning(
			path.Root("revocation_reason"),
			"Revocation reason ignored",
			"`revocation_reason` is ignored when `revoke_on_destroy` is false.",
		)
		return diags
	}

	return diags
}

func normalizeRevocationReasonString(value string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(value))
	normalized, ok := revocationReasonValues[key]
	return normalized, ok
}

func boolValue(value types.Bool, defaultValue bool) bool {
	if value.IsNull() || value.IsUnknown() {
		return defaultValue
	}
	return value.ValueBool()
}

func validateSubjectAlternativeNames(ctx context.Context, caps *client.Capabilities, profile *client.Profile, sanList types.List) diag.Diagnostics {
	var diags diag.Diagnostics

	if sanList.IsNull() || sanList.IsUnknown() {
		return diags
	}

	var sans []string
	diags = sanList.ElementsAs(ctx, &sans, false)
	if diags.HasError() {
		return diags
	}

	supported := map[string]struct{}{}
	if caps != nil {
		for _, t := range caps.SupportedSANTypes {
			supported[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
		}
	}
	if profile != nil && len(profile.SANTypes) > 0 {
		profileSupported := map[string]struct{}{}
		for _, t := range profile.SANTypes {
			profileSupported[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
		}

		if len(supported) == 0 {
			supported = profileSupported
		} else {
			for k := range supported {
				if _, ok := profileSupported[k]; !ok {
					delete(supported, k)
				}
			}
		}
	}

	if len(supported) == 0 {
		return diags
	}

	for idx, san := range sans {
		value := strings.TrimSpace(san)
		if value == "" {
			diags.AddAttributeError(
				path.Root("subject_alternative_names").AtListIndex(idx),
				"Empty subject alternative name",
				"Remove empty SAN entries or provide a valid value.",
			)
			continue
		}

		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			diags.AddAttributeError(
				path.Root("subject_alternative_names").AtListIndex(idx),
				"Invalid subject alternative name format",
				fmt.Sprintf("Value %q must use the form `<type>:<value>` (e.g., `dns:example.com`).", san),
			)
			continue
		}

		sanType := strings.ToLower(strings.TrimSpace(parts[0]))
		if _, ok := supported[sanType]; !ok {
			diags.AddAttributeError(
				path.Root("subject_alternative_names").AtListIndex(idx),
				"Unsupported subject alternative name type",
				fmt.Sprintf("Type %q is not supported by the tenant (supported types: %v).", sanType, caps.SupportedSANTypes),
			)
		}
	}

	return diags
}

func validateKeyRequirements(profile *client.Profile, parsed *csrAttributes, keyType types.String, keyLength types.Int64) diag.Diagnostics {
	var diags diag.Diagnostics

	var parsedKeyType string
	var parsedKeyLength int64
	if parsed != nil {
		parsedKeyType = parsed.KeyType
		parsedKeyLength = parsed.KeyLength
	}

	if parsedKeyType != "" && !keyType.IsNull() && !keyType.IsUnknown() {
		if !strings.EqualFold(parsedKeyType, keyType.ValueString()) {
			diags.AddAttributeError(
				path.Root("csr_key_type"),
				"CSR key type mismatch",
				fmt.Sprintf("CSR reports key type %q but `csr_key_type` was set to %q.", parsedKeyType, keyType.ValueString()),
			)
		}
	}

	if parsedKeyLength > 0 && !keyLength.IsNull() && !keyLength.IsUnknown() {
		if parsedKeyLength != keyLength.ValueInt64() {
			diags.AddAttributeError(
				path.Root("csr_key_length"),
				"CSR key length mismatch",
				fmt.Sprintf("CSR reports key length %d but `csr_key_length` was set to %d.", parsedKeyLength, keyLength.ValueInt64()),
			)
		}
	}

	if profile == nil {
		return diags
	}

	effectiveKeyType := parsedKeyType
	if effectiveKeyType == "" && !keyType.IsNull() && !keyType.IsUnknown() {
		effectiveKeyType = strings.TrimSpace(strings.ToLower(keyType.ValueString()))
	}

	if effectiveKeyType != "" && len(profile.KeyTypes) > 0 {
		value := strings.TrimSpace(strings.ToLower(effectiveKeyType))
		matched := false
		for _, t := range profile.KeyTypes {
			if strings.TrimSpace(strings.ToLower(t)) == value {
				matched = true
				break
			}
		}
		if !matched {
			diags.AddAttributeError(
				path.Root("csr_key_type"),
				"Unsupported key type",
				fmt.Sprintf("Key type %q is not supported by profile %q (supported: %v).", effectiveKeyType, profile.ID, profile.KeyTypes),
			)
		}
	}

	effectiveKeyLength := parsedKeyLength
	if effectiveKeyLength == 0 && !keyLength.IsNull() && !keyLength.IsUnknown() {
		effectiveKeyLength = keyLength.ValueInt64()
	}

	if effectiveKeyLength > 0 && len(profile.KeyLengths) > 0 {
		matched := false
		for _, v := range profile.KeyLengths {
			if int64(v) == effectiveKeyLength {
				matched = true
				break
			}
		}
		if !matched {
			diags.AddAttributeError(
				path.Root("csr_key_length"),
				"Unsupported key length",
				fmt.Sprintf("Key length %d is not supported by profile %q (supported: %v).", effectiveKeyLength, profile.ID, profile.KeyLengths),
			)
		}
	}

	return diags
}

type csrAttributes struct {
	KeyType   string
	KeyLength int64
	SANs      []string
}

func parseCSRAttributes(value types.String) (*csrAttributes, diag.Diagnostics) {
	var diags diag.Diagnostics

	if value.IsNull() || value.IsUnknown() {
		return nil, diags
	}

	block, _ := pem.Decode([]byte(value.ValueString()))
	if block == nil {
		diags.AddAttributeError(
			path.Root("csr_pem"),
			"Invalid CSR",
			"Value must be a PEM-encoded certificate signing request.",
		)
		return nil, diags
	}

	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		diags.AddAttributeError(
			path.Root("csr_pem"),
			"Invalid CSR",
			fmt.Sprintf("Unable to parse CSR: %v", err),
		)
		return nil, diags
	}

	if err := req.CheckSignature(); err != nil {
		diags.AddAttributeError(
			path.Root("csr_pem"),
			"Invalid CSR",
			fmt.Sprintf("CSR signature verification failed: %v", err),
		)
		return nil, diags
	}

	return &csrAttributes{
		KeyType:   publicKeyType(req.PublicKey),
		KeyLength: publicKeyLength(req.PublicKey),
		SANs:      extractSANs(req),
	}, diags
}

func publicKeyType(pub interface{}) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "rsa"
	case *ecdsa.PublicKey:
		return "ecdsa"
	case ed25519.PublicKey:
		return "ed25519"
	default:
		return ""
	}
}

func publicKeyLength(pub interface{}) int64 {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return int64(k.N.BitLen())
	case *ecdsa.PublicKey:
		if params := k.Params(); params != nil {
			return int64(params.BitSize)
		}
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

func extractSANs(req *x509.CertificateRequest) []string {
	var sans []string

	for _, dns := range req.DNSNames {
		if dns != "" {
			sans = append(sans, "dns:"+dns)
		}
	}

	for _, email := range req.EmailAddresses {
		if email != "" {
			sans = append(sans, "email:"+email)
		}
	}

	for _, ip := range req.IPAddresses {
		sans = append(sans, "ip:"+ip.String())
	}

	for _, uri := range req.URIs {
		sans = append(sans, "uri:"+uri.String())
	}

	return sans
}
