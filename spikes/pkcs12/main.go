package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/entrust/terraform-provider-entrustcagw/internal/client"
)

const defaultPingPath = "/v1/ping"

func main() {
	baseURL := mustGetEnv("ENTRUST_CAGW_BASE_URL")
	pkcs12Path := mustGetEnv("ENTRUST_CAGW_CLIENT_P12_PATH")
	pkcs12Password := mustGetEnv("ENTRUST_CAGW_CLIENT_P12_PASSWORD")
	caBundle := os.Getenv("ENTRUST_CAGW_TLS_CA_BUNDLE_PATH")

	tlsConfig, err := client.NewTLSConfig(client.TLSConfigInput{
		PKCS12Path:         pkcs12Path,
		PKCS12Password:     pkcs12Password,
		CustomCABundlePath: caBundle,
	})
	if err != nil {
		log.Fatalf("failed to build TLS config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s%s", baseURL, defaultPingPath), nil)
	if err != nil {
		log.Fatalf("creating request: %v", err)
	}
	req.Header.Set("X-Correlation-ID", uuid.NewString())

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: cloneTLSConfig(tlsConfig),
		},
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("ping request failed: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("ping response status: %s", resp.Status)
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return nil
	}
	return cfg.Clone()
}

func mustGetEnv(key string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Fatalf("environment variable %s is required", key)
	}
	return value
}
