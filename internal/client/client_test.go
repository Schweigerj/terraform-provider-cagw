package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

func TestGetCapabilities(t *testing.T) {
	client := newMockClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/capabilities" {
			t.Fatalf("expected /capabilities, got %s", req.URL.Path)
		}

		return jsonResponse(http.StatusOK, map[string]interface{}{
			"capabilities": map[string]interface{}{
				"supportedSanTypes":        []string{"dns"},
				"supportedKeyTypes":        []string{"rsa"},
				"supportedKeyLengths":      []int{2048},
				"supportsPkcs12Generation": true,
				"apiVersion":               "v1",
			},
		}), nil
	})

	caps, err := client.GetCapabilities(context.Background())
	if err != nil {
		t.Fatalf("GetCapabilities returned error: %v", err)
	}

	if caps.APIVersion != "v1" || !caps.SupportsPKCS12Generation {
		t.Fatalf("unexpected capabilities: %#v", caps)
	}
}

func TestEnrollCertificate(t *testing.T) {
	var capturedBody []byte
	client := newMockClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", req.Method)
		}
		if req.URL.Path != "/certificate-authorities/ca-123/enrollments" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		capturedBody = body

		return jsonResponse(http.StatusOK, map[string]interface{}{
			"certificate": map[string]interface{}{
				"serialNumber": "ABC123",
				"status":       "issued",
				"subjectDn":    "CN=example",
			},
		}), nil
	})

	cert, err := client.EnrollCertificate(context.Background(), "ca-123", CertificateEnrollmentRequest{
		ProfileID:               "profile-xyz",
		CSR:                     "-----BEGIN CERTIFICATE REQUEST-----",
		SubjectAlternativeNames: []string{"dns:example.com"},
	})
	if err != nil {
		t.Fatalf("EnrollCertificate returned error: %v", err)
	}

	if cert.SerialNumber != "ABC123" {
		t.Fatalf("unexpected serial number: %s", cert.SerialNumber)
	}
	if !bytes.Contains(capturedBody, []byte(`"profileId":"profile-xyz"`)) {
		t.Fatalf("expected profileId in request payload: %s", capturedBody)
	}
}

func TestRevokeCertificate(t *testing.T) {
	client := newMockClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", req.Method)
		}
		if req.URL.Path != "/certificates/ABC123/revoke" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		return jsonResponse(http.StatusNoContent, nil), nil
	})

	if err := client.RevokeCertificate(context.Background(), "ABC123", "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate returned error: %v", err)
	}
}

func TestHoldCertificate(t *testing.T) {
	client := newMockClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", req.Method)
		}
		if req.URL.Path != "/certificates/ABC123/hold" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		return jsonResponse(http.StatusNoContent, nil), nil
	})

	if err := client.HoldCertificate(context.Background(), "ABC123"); err != nil {
		t.Fatalf("HoldCertificate returned error: %v", err)
	}
}

func newMockClient(t *testing.T, handler func(*http.Request) (*http.Response, error)) *APIClient {
	t.Helper()

	baseURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parsing base url: %v", err)
	}

	return &APIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Transport: roundTripperFunc(handler),
		},
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body interface{}) *http.Response {
	var reader io.ReadCloser
	if body != nil {
		payload, _ := json.Marshal(body)
		reader = io.NopCloser(bytes.NewReader(payload))
	} else {
		reader = io.NopCloser(bytes.NewReader(nil))
	}

	return &http.Response{
		StatusCode: status,
		Body:       reader,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}
