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

// Only supports IPv4 per spec — community endpoint only handles IPv4.
func (g *GreyNoiseEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{detect.TypeIPv4}
}

func (g *GreyNoiseEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(g.SupportedTypes(), oType) {
		return unsupportedResult(g.Name()), ErrUnsupportedType
	}

	endpoint := fmt.Sprintf("%s/community/%s", g.baseURL, observable)
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
	case resp.StatusCode == http.StatusNotFound:
		// IP not seen by GreyNoise — valid result.
		return &model.SourceResult{
			Name:   g.Name(),
			Status: "ok",
			Data: map[string]any{
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
		IP             string `json:"ip"`
		Noise          bool   `json:"noise"`
		RIOT           bool   `json:"riot"`
		Classification string `json:"classification"`
		Name           string `json:"name"`
		Link           string `json:"link"`
		Message        string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return errResult(g.Name(), fmt.Sprintf("decode error: %v", err)), nil
	}

	data := map[string]any{
		"noise":          raw.Noise,
		"riot":           raw.RIOT,
		"classification": raw.Classification,
		"name":           raw.Name,
		"link":           raw.Link,
	}

	return &model.SourceResult{
		Name:   g.Name(),
		Status: "ok",
		Data:   data,
		RawURL: raw.Link,
	}, nil
}
