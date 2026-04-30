package enricher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctrlaltdean/observer/internal/detect"
)

func TestGreyNoiseEnrich_Malicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("key") == "" {
			t.Error("missing GreyNoise API key header")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ip":             "1.2.3.4",
			"noise":          true,
			"riot":           false,
			"classification": "malicious",
			"name":           "",
			"link":           "https://viz.greynoise.io/ip/1.2.3.4",
		})
	}))
	defer srv.Close()

	e := NewGreyNoise("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s: %s", result.Status, result.ErrorMessage)
	}
	if result.Data["noise"] != true {
		t.Error("expected noise=true")
	}
	if result.Data["classification"] != "malicious" {
		t.Errorf("expected classification=malicious, got %v", result.Data["classification"])
	}
}

func TestGreyNoiseEnrich_RIOT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"ip":             "8.8.8.8",
			"noise":          false,
			"riot":           true,
			"classification": "benign",
			"name":           "Google LLC",
			"link":           "https://viz.greynoise.io/ip/8.8.8.8",
		})
	}))
	defer srv.Close()

	e := NewGreyNoise("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "8.8.8.8", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Data["riot"] != true {
		t.Error("expected riot=true")
	}
	if result.Data["name"] != "Google LLC" {
		t.Errorf("expected name=Google LLC, got %v", result.Data["name"])
	}
}

func TestGreyNoiseEnrich_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	e := NewGreyNoise("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "192.0.2.1", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok for 404, got %s", result.Status)
	}
	if result.Data["noise"] != false {
		t.Error("expected noise=false for unseen IP")
	}
}

func TestGreyNoiseEnrich_UnsupportedType(t *testing.T) {
	e := NewGreyNoise("test-key")
	result, err := e.Enrich(context.Background(), "example.com", detect.TypeDomain)
	if err != ErrUnsupportedType {
		t.Errorf("expected ErrUnsupportedType, got %v", err)
	}
	if result.Status != "unsupported" {
		t.Errorf("expected unsupported, got %s", result.Status)
	}
}

func TestGreyNoiseEnrich_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := NewGreyNoise("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", result.Status)
	}
}
