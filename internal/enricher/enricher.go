package enricher

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ctrlaltdean/observer/internal/detect"
	"github.com/ctrlaltdean/observer/internal/model"
)

// ErrUnsupportedType is returned when an enricher is called with a type it does not handle.
var ErrUnsupportedType = errors.New("unsupported observable type")

// Enricher is implemented by every enrichment source.
type Enricher interface {
	Name() string
	SupportedTypes() []detect.ObservableType
	Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error)
}

// newHTTPClient returns a shared client with a fixed timeout.
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// unsupportedResult returns a standard "unsupported" SourceResult.
func unsupportedResult(name string) *model.SourceResult {
	return &model.SourceResult{
		Name:   name,
		Status: "unsupported",
		Data:   map[string]any{},
	}
}

// errResult returns a standard "error" SourceResult.
func errResult(name, msg string) *model.SourceResult {
	return &model.SourceResult{
		Name:         name,
		Status:       "error",
		ErrorMessage: msg,
		Data:         map[string]any{},
	}
}

// rateLimitedResult returns a standard "rate_limited" SourceResult.
func rateLimitedResult(name string) *model.SourceResult {
	return &model.SourceResult{
		Name:         name,
		Status:       "rate_limited",
		ErrorMessage: "rate limited by " + name,
		Data:         map[string]any{},
	}
}

// supportsType is a helper used by all enrichers.
func supportsType(supported []detect.ObservableType, t detect.ObservableType) bool {
	for _, s := range supported {
		if s == t {
			return true
		}
	}
	return false
}
