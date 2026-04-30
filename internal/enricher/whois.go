package enricher

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"

	"github.com/ctrlaltdean/observer/internal/detect"
	"github.com/ctrlaltdean/observer/internal/model"
)

type WHOISEnricher struct{}

func NewWHOIS() *WHOISEnricher { return &WHOISEnricher{} }

func (w *WHOISEnricher) Name() string { return "whois" }

func (w *WHOISEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{
		detect.TypeIPv4, detect.TypeIPv6, detect.TypeDomain, detect.TypeURL,
	}
}

func (w *WHOISEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(w.SupportedTypes(), oType) {
		return unsupportedResult(w.Name()), ErrUnsupportedType
	}

	switch oType {
	case detect.TypeIPv4, detect.TypeIPv6:
		return w.enrichIP(ctx, observable)
	case detect.TypeDomain:
		return w.enrichDomain(observable)
	case detect.TypeURL:
		// Extract domain from URL and do WHOIS on it.
		domain := extractDomainFromURL(observable)
		if domain == "" {
			return errResult(w.Name(), "could not extract domain from URL"), nil
		}
		return w.enrichDomain(domain)
	default:
		return unsupportedResult(w.Name()), ErrUnsupportedType
	}
}

func (w *WHOISEnricher) enrichIP(ctx context.Context, ip string) (*model.SourceResult, error) {
	data := map[string]any{}

	// rDNS lookup.
	ptrs, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err == nil && len(ptrs) > 0 {
		// Strip trailing dots from PTR records.
		clean := make([]string, len(ptrs))
		for i, p := range ptrs {
			clean[i] = strings.TrimSuffix(p, ".")
		}
		data["ptr_records"] = clean
	}

	// WHOIS lookup on the IP itself (returns ASN/org info from RIR).
	raw, err := whois.Whois(ip)
	if err != nil {
		if len(data) > 0 {
			// We have PTR data — return partial success.
			return &model.SourceResult{
				Name:   w.Name(),
				Status: "ok",
				Data:   data,
			}, nil
		}
		return errResult(w.Name(), fmt.Sprintf("WHOIS query failed: %v", err)), nil
	}

	parsed, err := whoisparser.Parse(raw)
	if err == nil {
		if parsed.Registrar != nil && parsed.Registrar.Name != "" {
			data["registrar"] = parsed.Registrar.Name
		}
		if parsed.Registrant != nil {
			org := parsed.Registrant.Organization
			if org == "" {
				org = "Redacted"
			}
			data["registrant_organization"] = org
		}
		if parsed.Domain != nil {
			setIfNotEmpty(data, "created_date", parsed.Domain.CreatedDate)
			setIfNotEmpty(data, "updated_date", parsed.Domain.UpdatedDate)
			setIfNotEmpty(data, "expiration_date", parsed.Domain.ExpirationDate)
			if len(parsed.Domain.NameServers) > 0 {
				data["name_servers"] = parsed.Domain.NameServers
			}
			if len(parsed.Domain.Status) > 0 {
				data["status"] = parsed.Domain.Status
			}
		}
	}

	return &model.SourceResult{
		Name:   w.Name(),
		Status: "ok",
		Data:   data,
	}, nil
}

func (w *WHOISEnricher) enrichDomain(domain string) (*model.SourceResult, error) {
	raw, err := whois.Whois(domain)
	if err != nil {
		return errResult(w.Name(), fmt.Sprintf("WHOIS query failed: %v", err)), nil
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		// Return raw data if parsing failed (some TLDs have non-standard formats).
		return &model.SourceResult{
			Name:   w.Name(),
			Status: "ok",
			Data:   map[string]any{"raw_note": "WHOIS response could not be parsed"},
		}, nil
	}

	data := map[string]any{}

	if parsed.Registrar != nil {
		setIfNotEmpty(data, "registrar", parsed.Registrar.Name)
	}
	if parsed.Registrant != nil {
		org := parsed.Registrant.Organization
		if org == "" {
			org = "Redacted"
		}
		data["registrant_organization"] = org
	}
	if parsed.Domain != nil {
		setIfNotEmpty(data, "created_date", parsed.Domain.CreatedDate)
		setIfNotEmpty(data, "updated_date", parsed.Domain.UpdatedDate)
		setIfNotEmpty(data, "expiration_date", parsed.Domain.ExpirationDate)
		if len(parsed.Domain.NameServers) > 0 {
			data["name_servers"] = parsed.Domain.NameServers
		}
		if len(parsed.Domain.Status) > 0 {
			data["status"] = parsed.Domain.Status
		}
	}

	return &model.SourceResult{
		Name:   w.Name(),
		Status: "ok",
		Data:   data,
		RawURL: fmt.Sprintf("https://lookup.icann.org/lookup?name=%s", domain),
	}, nil
}

func setIfNotEmpty(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func extractDomainFromURL(rawURL string) string {
	// Simple extraction: strip scheme and take the host part.
	s := rawURL
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i != -1 {
		s = s[:i]
	}
	// Strip port if present.
	if i := strings.LastIndex(s, ":"); i != -1 {
		s = s[:i]
	}
	return s
}
