package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ctrlaltdean/observer/internal/detect"
	"github.com/ctrlaltdean/observer/internal/model"
)

type GreyNoiseEnricher struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

func NewGreyNoise(apiKey string) *GreyNoiseEnricher {
	return &GreyNoiseEnricher{
		apiKey:  apiKey,
		baseURL: "https://api.greynoise.io/v3",
		client:  newHTTPClient(),
	}
}

func (g *GreyNoiseEnricher) Name() string { return "greynoise" }

func (g *GreyNoiseEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{detect.TypeIPv4}
}

func (g *GreyNoiseEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(g.SupportedTypes(), oType) {
		return unsupportedResult(g.Name()), ErrUnsupportedType
	}

	// /v3/context returns full context for a single IP (requires API key).
	endpoint := fmt.Sprintf("%s/context/%s", g.baseURL, observable)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errResult(g.Name(), fmt.Sprintf("request error: %v", err)), nil
	}
	req.Header.Set("key", g.apiKey)

	resp, err := g.client.Do(req)
	if err != nil {
		return errResult(g.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return rateLimitedResult(g.Name()), nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errResult(g.Name(), "invalid or missing API key"), nil
	case resp.StatusCode == http.StatusNotFound:
		// IP not in GreyNoise dataset.
		return &model.SourceResult{
			Name:   g.Name(),
			Status: "ok",
			Data: map[string]any{
				"seen":           false,
				"noise":          false,
				"riot":           false,
				"classification": "unknown",
			},
			RawURL: fmt.Sprintf("https://viz.greynoise.io/ip/%s", observable),
		}, nil
	case resp.StatusCode >= 500:
		return errResult(g.Name(), fmt.Sprintf("server error: HTTP %d", resp.StatusCode)), nil
	case resp.StatusCode >= 400:
		return errResult(g.Name(), fmt.Sprintf("client error: HTTP %d", resp.StatusCode)), nil
	}

	var raw struct {
		IP             string   `json:"ip"`
		Seen           bool     `json:"seen"`
		Noise          bool     `json:"noise"`
		RIOT           bool     `json:"riot"`
		Classification string   `json:"classification"`
		Name           string   `json:"name"`
		Link           string   `json:"link"`
		Tags           []string `json:"tags"`
		FirstSeen      string   `json:"first_seen"`
		LastSeen       string   `json:"last_seen"`
		Country        string   `json:"country"`
		CountryCode    string   `json:"country_code"`
		City           string   `json:"city"`
		Organization   string   `json:"organization"`
		ASN            string   `json:"asn"`
		OS             string   `json:"os"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return errResult(g.Name(), fmt.Sprintf("decode error: %v", err)), nil
	}

	data := map[string]any{
		"seen":           raw.Seen,
		"noise":          raw.Noise,
		"riot":           raw.RIOT,
		"classification": raw.Classification,
	}
	if raw.Name != "" {
		data["name"] = raw.Name
	}
	if len(raw.Tags) > 0 {
		data["tags"] = raw.Tags
	}
	if raw.FirstSeen != "" {
		data["first_seen"] = raw.FirstSeen
	}
	if raw.LastSeen != "" {
		data["last_seen"] = raw.LastSeen
	}
	if raw.Country != "" {
		data["country"] = raw.Country
	}
	if raw.Organization != "" {
		data["organization"] = raw.Organization
	}
	if raw.ASN != "" {
		data["asn"] = raw.ASN
	}
	if raw.OS != "" {
		data["os"] = raw.OS
	}

	vizURL := fmt.Sprintf("https://viz.greynoise.io/ip/%s", observable)
	if raw.Link != "" {
		vizURL = raw.Link
	}

	return &model.SourceResult{
		Name:   g.Name(),
		Status: "ok",
		Data:   data,
		RawURL: vizURL,
	}, nil
}
