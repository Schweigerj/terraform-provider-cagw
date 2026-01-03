package provider

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	envBaseURL            = "ENTRUST_CAGW_BASE_URL"
	envClientP12Path      = "ENTRUST_CAGW_CLIENT_P12_PATH"
	envClientP12Password  = "ENTRUST_CAGW_CLIENT_P12_PASSWORD"
	envTLSCABundlePath    = "ENTRUST_CAGW_TLS_CA_BUNDLE_PATH"
	envProxyURL           = "ENTRUST_CAGW_PROXY_URL"
	envInsecureSkipVerify = "ENTRUST_CAGW_INSECURE_SKIP_VERIFY"
	envCorrelationID      = "ENTRUST_CAGW_CORRELATION_ID"
)

type providerModel struct {
	BaseURL            types.String `tfsdk:"base_url"`
	ClientP12Path      types.String `tfsdk:"client_p12_path"`
	ClientP12Password  types.String `tfsdk:"client_p12_password"`
	TLSCABundlePath    types.String `tfsdk:"tls_ca_bundle_path"`
	ProxyURL           types.String `tfsdk:"proxy_url"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
	CorrelationID      types.String `tfsdk:"correlation_id"`
}

type ProviderData struct {
	BaseURL            string
	ClientP12Path      string
	ClientP12Password  string
	TLSCABundlePath    string
	ProxyURL           string
	InsecureSkipVerify bool
	CorrelationID      string
}

func (m providerModel) expand() (*ProviderData, diag.Diagnostics) {
	var diags diag.Diagnostics

	baseURL, d := readStringValue("base_url", m.BaseURL, envBaseURL, true)
	diags.Append(d...)

	p12Path, d := readStringValue("client_p12_path", m.ClientP12Path, envClientP12Path, true)
	diags.Append(d...)

	p12Password, d := readStringValue("client_p12_password", m.ClientP12Password, envClientP12Password, true)
	diags.Append(d...)

	caBundlePath, d := readStringValue("tls_ca_bundle_path", m.TLSCABundlePath, envTLSCABundlePath, false)
	diags.Append(d...)

	proxyURL, d := readStringValue("proxy_url", m.ProxyURL, envProxyURL, false)
	diags.Append(d...)

	correlationID, d := readStringValue("correlation_id", m.CorrelationID, envCorrelationID, false)
	diags.Append(d...)

	insecure, d := readBoolValue("insecure_skip_verify", m.InsecureSkipVerify, envInsecureSkipVerify)
	diags.Append(d...)

	if diags.HasError() {
		return nil, diags
	}

	return &ProviderData{
		BaseURL:            baseURL,
		ClientP12Path:      p12Path,
		ClientP12Password:  p12Password,
		TLSCABundlePath:    caBundlePath,
		ProxyURL:           proxyURL,
		InsecureSkipVerify: insecure,
		CorrelationID:      correlationID,
	}, diags
}

func readStringValue(attrName string, attr types.String, envKey string, required bool) (string, diag.Diagnostics) {
	var diags diag.Diagnostics

	if !attr.IsNull() && !attr.IsUnknown() {
		value := strings.TrimSpace(attr.ValueString())
		if required && value == "" {
			diags.AddAttributeError(path.Root(attrName), fmt.Sprintf("Invalid value for %s", attrName), "A non-empty value is required.")
			return "", diags
		}

		return value, diags
	}

	if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
		return value, diags
	}

	if required {
		diags.AddAttributeError(path.Root(attrName), fmt.Sprintf("Missing %s", attrName), fmt.Sprintf("Set the %s attribute or %s environment variable.", attrName, envKey))
	}

	return "", diags
}

func readBoolValue(attrName string, attr types.Bool, envKey string) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	if !attr.IsNull() && !attr.IsUnknown() {
		return attr.ValueBool(), diags
	}

	if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			diags.AddAttributeError(path.Root(attrName), fmt.Sprintf("Invalid boolean for %s", attrName), fmt.Sprintf("Environment variable %s must be a boolean value (true/false).", envKey))
			return false, diags
		}
		return parsed, diags
	}

	return false, diags
}
