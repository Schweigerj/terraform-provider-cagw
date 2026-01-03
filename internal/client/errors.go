package client

import (
	"errors"
	"fmt"
	"net/http"
)

// APIError captures HTTP-level failures with additional metadata useful for diagnostics.
type APIError struct {
	Operation     string
	StatusCode    int
	Message       string
	CorrelationID string
	Err           error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e == nil {
		return ""
	}

	msg := e.Message
	if msg == "" && e.Err != nil {
		msg = e.Err.Error()
	}
	if msg == "" {
		msg = "Entrust CA Gateway API error"
	}

	if e.Operation != "" {
		msg = fmt.Sprintf("%s: %s", e.Operation, msg)
	}
	if e.StatusCode > 0 {
		msg = fmt.Sprintf("%s (status %d)", msg, e.StatusCode)
	}
	if e.CorrelationID != "" {
		msg = fmt.Sprintf("%s (correlation_id=%s)", msg, e.CorrelationID)
	}

	return msg
}

// Unwrap exposes the nested error (if any).
func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsNotFound returns true when the error represents a HTTP 404 response.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}
