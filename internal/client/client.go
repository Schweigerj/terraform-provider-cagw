package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxRequestRetries = 3
	baseRetryDelay    = 2 * time.Second
	maxRetryDelay     = 30 * time.Second
)

// Config contains the provider-level options for the API client.
type Config struct {
	BaseURL            string
	PKCS12Path         string
	PKCS12Password     string
	TLSCABundlePath    string
	ProxyURL           string
	InsecureSkipVerify bool
	CorrelationID      string
	Timeout            time.Duration
}

// APIClient executes requests against Entrust CA Gateway.
type APIClient struct {
	baseURL       *url.URL
	httpClient    *http.Client
	correlationID string
}

// PingResult captures the output from the ping endpoint.
type PingResult struct {
	StatusCode     int
	ResponseBody   string
	CorrelationID  string
	Endpoint       string
	RequestLatency time.Duration
}

// CertificateAuthority represents Entrust CA Gateway CA metadata.
type CertificateAuthority struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Status             string   `json:"status"`
	Description        string   `json:"description"`
	ProfileIDs         []string `json:"profileIds"`
	EnrollmentEndpoint string   `json:"enrollmentEndpoint"`
	CreatedAt          string   `json:"createdAt"`
	UpdatedAt          string   `json:"updatedAt"`
}

// New creates a configured API client using the provided PKCS#12 credentials.
func New(cfg Config) (*APIClient, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("base URL is required")
	}

	tlsConfig, err := NewTLSConfig(TLSConfigInput{
		PKCS12Path:         cfg.PKCS12Path,
		PKCS12Password:     cfg.PKCS12Password,
		CustomCABundlePath: cfg.TLSCABundlePath,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}

	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL %q: %w", cfg.BaseURL, err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig.Clone(),
	}

	if strings.TrimSpace(cfg.ProxyURL) != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	return &APIClient{
		baseURL:       baseURL,
		httpClient:    httpClient,
		correlationID: strings.TrimSpace(cfg.CorrelationID),
	}, nil
}

// Ping performs a GET request against the ping endpoint to validate connectivity.
func (c *APIClient) Ping(ctx context.Context) (*PingResult, error) {
	const pingPath = "/ping"

	start := time.Now()
	resp, corrID, err := c.doRequest(ctx, http.MethodGet, pingPath, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "ping",
			Message:       fmt.Sprintf("reading response body: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "ping",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	return &PingResult{
		StatusCode:     resp.StatusCode,
		ResponseBody:   string(body),
		CorrelationID:  corrID,
		Endpoint:       c.baseURL.ResolveReference(&url.URL{Path: pingPath}).String(),
		RequestLatency: time.Since(start),
	}, nil
}

func (c *APIClient) doRequest(ctx context.Context, method, path string, body []byte, headers map[string]string) (*http.Response, string, error) {
	if c == nil || c.httpClient == nil {
		return nil, "", fmt.Errorf("api client is not configured")
	}

	endpointURL := c.baseURL.ResolveReference(&url.URL{Path: path})
	operation := fmt.Sprintf("%s %s", method, endpointURL.String())
	corrID := c.correlationID
	if corrID == "" {
		corrID = uuid.NewString()
	}

	var lastErr error
	for attempt := 0; attempt < maxRequestRetries; attempt++ {
		var reader io.Reader
		if len(body) > 0 {
			reader = bytes.NewReader(body)
		}

		req, err := http.NewRequestWithContext(ctx, method, endpointURL.String(), reader)
		if err != nil {
			return nil, corrID, &APIError{
				Operation:     operation,
				Message:       fmt.Sprintf("creating request: %v", err),
				CorrelationID: corrID,
				Err:           err,
			}
		}

		req.Header.Set("X-Correlation-ID", corrID)
		req.Header.Set("Accept", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = &APIError{
				Operation:     operation,
				Message:       fmt.Sprintf("performing request: %v", err),
				CorrelationID: corrID,
				Err:           err,
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, corrID, lastErr
			}

			if attempt == maxRequestRetries-1 {
				return nil, corrID, lastErr
			}

			if err := sleepWithContext(ctx, retryBackoffDuration(attempt)); err != nil {
				return nil, corrID, lastErr
			}
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRequestRetries-1 {
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			if wait <= 0 {
				wait = retryBackoffDuration(attempt)
			}
			resp.Body.Close()

			if err := sleepWithContext(ctx, wait); err != nil {
				return nil, corrID, &APIError{
					Operation:     operation,
					Message:       fmt.Sprintf("request cancelled while backing off after 429: %v", err),
					CorrelationID: corrID,
					Err:           err,
				}
			}
			continue
		}

		return resp, corrID, nil
	}

	if lastErr == nil {
		lastErr = &APIError{
			Operation:     operation,
			Message:       "request failed after retries",
			CorrelationID: corrID,
		}
	}

	return nil, corrID, lastErr
}

// ListCertificateAuthorities returns every certificate authority visible to the caller.
func (c *APIClient) ListCertificateAuthorities(ctx context.Context) ([]CertificateAuthority, error) {
	resp, corrID, err := c.doRequest(ctx, http.MethodGet, "/certificate-authorities", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "list certificate authorities",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "list certificate authorities",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	var listResp certificateAuthorityListResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return nil, &APIError{
			Operation:     "list certificate authorities",
			Message:       fmt.Sprintf("decoding response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	authorities := listResp.CertificateAuthorities
	if len(authorities) == 0 {
		authorities = listResp.Items
	}

	return authorities, nil
}

// GetCertificateAuthority fetches a single certificate authority by ID.
func (c *APIClient) GetCertificateAuthority(ctx context.Context, id string) (*CertificateAuthority, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("certificate authority id is required")
	}

	path := fmt.Sprintf("/certificate-authorities/%s", url.PathEscape(id))

	resp, corrID, err := c.doRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "get certificate authority",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{
			Operation:     "get certificate authority",
			StatusCode:    http.StatusNotFound,
			Message:       fmt.Sprintf("certificate authority %q not found", id),
			CorrelationID: corrID,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "get certificate authority",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	var ca CertificateAuthority
	if err := json.Unmarshal(body, &ca); err == nil && ca.ID != "" {
		return &ca, nil
	}

	var wrapped struct {
		CertificateAuthority CertificateAuthority `json:"certificateAuthority"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, &APIError{
			Operation:     "get certificate authority",
			Message:       fmt.Sprintf("decoding response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if wrapped.CertificateAuthority.ID == "" {
		return nil, &APIError{
			Operation:     "get certificate authority",
			Message:       "response missing certificateAuthority.id",
			CorrelationID: corrID,
		}
	}

	return &wrapped.CertificateAuthority, nil
}

type certificateAuthorityListResponse struct {
	Items                  []CertificateAuthority `json:"items"`
	CertificateAuthorities []CertificateAuthority `json:"certificateAuthorities"`
}

// ListProfiles returns all enrollment profiles.
func (c *APIClient) ListProfiles(ctx context.Context) ([]Profile, error) {
	resp, corrID, err := c.doRequest(ctx, http.MethodGet, "/profiles", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "list profiles",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "list profiles",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	var list struct {
		Profiles []Profile `json:"profiles"`
		Items    []Profile `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, &APIError{
			Operation:     "list profiles",
			Message:       fmt.Sprintf("decoding response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if len(list.Profiles) > 0 {
		return list.Profiles, nil
	}
	return list.Items, nil
}

// GetProfile retrieves a specific enrollment profile by ID.
func (c *APIClient) GetProfile(ctx context.Context, id string) (*Profile, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("profile id is required")
	}

	path := fmt.Sprintf("/profiles/%s", url.PathEscape(id))
	resp, corrID, err := c.doRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "get profile",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{
			Operation:     "get profile",
			StatusCode:    http.StatusNotFound,
			Message:       fmt.Sprintf("profile %q not found", id),
			CorrelationID: corrID,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "get profile",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	var profile Profile
	if err := json.Unmarshal(body, &profile); err == nil && profile.ID != "" {
		return &profile, nil
	}

	var wrapper struct {
		Profile Profile `json:"profile"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, &APIError{
			Operation:     "get profile",
			Message:       fmt.Sprintf("decoding response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}
	if wrapper.Profile.ID == "" {
		return nil, &APIError{
			Operation:     "get profile",
			Message:       "response missing profile.id",
			CorrelationID: corrID,
		}
	}

	return &wrapper.Profile, nil
}

// GetCertificate fetches a certificate by serial number.
func (c *APIClient) GetCertificate(ctx context.Context, serial string) (*Certificate, error) {
	if strings.TrimSpace(serial) == "" {
		return nil, fmt.Errorf("certificate serial number is required")
	}

	path := fmt.Sprintf("/certificates/%s", url.PathEscape(serial))
	resp, corrID, err := c.doRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "get certificate",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{
			Operation:     "get certificate",
			StatusCode:    http.StatusNotFound,
			Message:       fmt.Sprintf("certificate %q not found", serial),
			CorrelationID: corrID,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "get certificate",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	var cert Certificate
	if err := json.Unmarshal(body, &cert); err == nil && cert.SerialNumber != "" {
		return &cert, nil
	}

	var wrapper struct {
		Certificate Certificate `json:"certificate"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, &APIError{
			Operation:     "get certificate",
			Message:       fmt.Sprintf("decoding response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}
	if wrapper.Certificate.SerialNumber == "" {
		return nil, &APIError{
			Operation:     "get certificate",
			Message:       "response missing certificate.serialNumber",
			CorrelationID: corrID,
		}
	}

	return &wrapper.Certificate, nil
}

// EnrollCertificate issues a new certificate under the given certificate authority.
func (c *APIClient) EnrollCertificate(ctx context.Context, caID string, request CertificateEnrollmentRequest) (*Certificate, error) {
	if strings.TrimSpace(caID) == "" {
		return nil, fmt.Errorf("certificate authority id is required")
	}
	if strings.TrimSpace(request.CSR) == "" {
		return nil, fmt.Errorf("csr is required")
	}
	if strings.TrimSpace(request.ProfileID) == "" {
		return nil, fmt.Errorf("profile id is required")
	}

	path := fmt.Sprintf("/certificate-authorities/%s/enrollments", url.PathEscape(caID))
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encoding enrollment request: %w", err)
	}

	resp, corrID, err := c.doRequest(ctx, http.MethodPost, path, payload, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "enroll certificate",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "enroll certificate",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	var cert Certificate
	if err := json.Unmarshal(body, &cert); err == nil && cert.SerialNumber != "" {
		return &cert, nil
	}

	var wrapper struct {
		Certificate Certificate `json:"certificate"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, &APIError{
			Operation:     "enroll certificate",
			Message:       fmt.Sprintf("decoding response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	return &wrapper.Certificate, nil
}

// RevokeCertificate revokes the certificate with the provided serial number.
func (c *APIClient) RevokeCertificate(ctx context.Context, serial, reason string) error {
	if strings.TrimSpace(serial) == "" {
		return fmt.Errorf("certificate serial number is required")
	}

	path := fmt.Sprintf("/certificates/%s/revoke", url.PathEscape(serial))
	payload, err := json.Marshal(CertificateRevokeRequest{Reason: reason})
	if err != nil {
		return fmt.Errorf("encoding revoke request: %w", err)
	}

	resp, corrID, err := c.doRequest(ctx, http.MethodPost, path, payload, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &APIError{
			Operation:     "revoke certificate",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return &APIError{
			Operation:     "revoke certificate",
			StatusCode:    http.StatusNotFound,
			Message:       fmt.Sprintf("certificate %q not found", serial),
			CorrelationID: corrID,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{
			Operation:     "revoke certificate",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	return nil
}

// HoldCertificate places the certificate on hold (if supported by the tenant).
func (c *APIClient) HoldCertificate(ctx context.Context, serial string) error {
	if strings.TrimSpace(serial) == "" {
		return fmt.Errorf("certificate serial number is required")
	}

	path := fmt.Sprintf("/certificates/%s/hold", url.PathEscape(serial))
	resp, corrID, err := c.doRequest(ctx, http.MethodPost, path, nil, map[string]string{
		"Content-Type": "application/json",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &APIError{
			Operation:     "hold certificate",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return &APIError{
			Operation:     "hold certificate",
			StatusCode:    http.StatusNotFound,
			Message:       fmt.Sprintf("certificate %q not found", serial),
			CorrelationID: corrID,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{
			Operation:     "hold certificate",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	return nil
}

// GetCapabilities returns tenant-level capability information.
func (c *APIClient) GetCapabilities(ctx context.Context) (*Capabilities, error) {
	resp, corrID, err := c.doRequest(ctx, http.MethodGet, "/capabilities", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &APIError{
			Operation:     "get capabilities",
			Message:       fmt.Sprintf("reading response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Operation:     "get capabilities",
			StatusCode:    resp.StatusCode,
			Message:       string(body),
			CorrelationID: corrID,
		}
	}

	var caps Capabilities
	if err := json.Unmarshal(body, &caps); err == nil && (len(caps.SupportedSANTypes) > 0 || caps.APIVersion != "") {
		return &caps, nil
	}

	var wrapper struct {
		Capabilities Capabilities `json:"capabilities"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, &APIError{
			Operation:     "get capabilities",
			Message:       fmt.Sprintf("decoding response: %v", err),
			CorrelationID: corrID,
			Err:           err,
		}
	}

	return &wrapper.Capabilities, nil
}

func retryBackoffDuration(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	delay := baseRetryDelay * time.Duration(1<<attempt)
	if delay > maxRetryDelay {
		return maxRetryDelay
	}
	return delay
}

func parseRetryAfter(value string) time.Duration {
	if strings.TrimSpace(value) == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		if seconds < 0 {
			seconds = 0
		}
		return time.Duration(seconds) * time.Second
	}

	if ts, err := http.ParseTime(value); err == nil {
		return time.Until(ts)
	}

	return 0
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Profile contains enrollment profile metadata.
type Profile struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Status          string   `json:"status"`
	Description     string   `json:"description"`
	CertificateType string   `json:"certificateType"`
	Subject         string   `json:"subject"`
	KeyTypes        []string `json:"keyTypes"`
	KeyLengths      []int    `json:"keyLengths"`
	SANTypes        []string `json:"sanTypes"`
	CreatedAt       string   `json:"createdAt"`
	UpdatedAt       string   `json:"updatedAt"`
}

// Certificate models an issued certificate.
type Certificate struct {
	SerialNumber            string   `json:"serialNumber"`
	Status                  string   `json:"status"`
	CertificateAuthorityID  string   `json:"certificateAuthorityId"`
	ProfileID               string   `json:"profileId"`
	SubjectDN               string   `json:"subjectDn"`
	IssuerDN                string   `json:"issuerDn"`
	SubjectAlternativeNames []string `json:"subjectAlternativeNames"`
	NotBefore               string   `json:"notBefore"`
	NotAfter                string   `json:"notAfter"`
	CertificatePEM          string   `json:"certificatePem"`
	CertificateChainPEM     []string `json:"certificateChainPem"`
	PKCS12                  string   `json:"pkcs12"`
	RevocationReason        string   `json:"revocationReason"`
	CreatedAt               string   `json:"createdAt"`
	UpdatedAt               string   `json:"updatedAt"`
}

// CertificateEnrollmentRequest defines the payload for certificate issuance.
type CertificateEnrollmentRequest struct {
	ProfileID               string   `json:"profileId"`
	CSR                     string   `json:"csr"`
	SubjectAlternativeNames []string `json:"subjectAlternativeNames,omitempty"`
	PKCS12Passphrase        string   `json:"pkcs12Passphrase,omitempty"`
	GeneratePKCS12          bool     `json:"generatePkcs12,omitempty"`
}

// CertificateRevokeRequest captures revocation parameters.
type CertificateRevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// Capabilities describes tenant-wide features.
type Capabilities struct {
	SupportedSANTypes         []string `json:"supportedSanTypes"`
	SupportedKeyTypes         []string `json:"supportedKeyTypes"`
	SupportedKeyLengths       []int    `json:"supportedKeyLengths"`
	SupportsPKCS12Generation  bool     `json:"supportsPkcs12Generation"`
	SupportsCSRValidationOnly bool     `json:"supportsCsrValidationOnly"`
	SupportsCertificateHold   bool     `json:"supportsCertificateHold"`
	SupportsRecovery          bool     `json:"supportsRecovery"`
	APIVersion                string   `json:"apiVersion"`
}
