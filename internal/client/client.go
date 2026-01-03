package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
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
	resp, corrID, err := c.doRequest(ctx, http.MethodGet, pingPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading ping response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ping endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	return &PingResult{
		StatusCode:     resp.StatusCode,
		ResponseBody:   string(body),
		CorrelationID:  corrID,
		Endpoint:       c.baseURL.ResolveReference(&url.URL{Path: pingPath}).String(),
		RequestLatency: time.Since(start),
	}, nil
}

func (c *APIClient) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, string, error) {
	if c == nil || c.httpClient == nil {
		return nil, "", fmt.Errorf("api client is not configured")
	}

	endpointURL := c.baseURL.ResolveReference(&url.URL{Path: path})

	req, err := http.NewRequestWithContext(ctx, method, endpointURL.String(), body)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}

	corrID := c.correlationID
	if corrID == "" {
		corrID = uuid.NewString()
	}
	req.Header.Set("X-Correlation-ID", corrID)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, corrID, fmt.Errorf("performing request (%s %s): %w", method, endpointURL, err)
	}

	return resp, corrID, nil
}

// ListCertificateAuthorities returns every certificate authority visible to the caller.
func (c *APIClient) ListCertificateAuthorities(ctx context.Context) ([]CertificateAuthority, error) {
	resp, _, err := c.doRequest(ctx, http.MethodGet, "/certificate-authorities", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading certificate authorities response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list certificate authorities failed (%d): %s", resp.StatusCode, string(body))
	}

	var listResp certificateAuthorityListResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return nil, fmt.Errorf("decoding certificate authorities: %w", err)
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

	resp, _, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading certificate authority response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("certificate authority %q not found", id)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("get certificate authority failed (%d): %s", resp.StatusCode, string(body))
	}

	var ca CertificateAuthority
	if err := json.Unmarshal(body, &ca); err == nil && ca.ID != "" {
		return &ca, nil
	}

	var wrapped struct {
		CertificateAuthority CertificateAuthority `json:"certificateAuthority"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("decoding certificate authority: %w", err)
	}

	if wrapped.CertificateAuthority.ID == "" {
		return nil, fmt.Errorf("certificate authority response missing ID")
	}

	return &wrapped.CertificateAuthority, nil
}

type certificateAuthorityListResponse struct {
	Items                  []CertificateAuthority `json:"items"`
	CertificateAuthorities []CertificateAuthority `json:"certificateAuthorities"`
}
