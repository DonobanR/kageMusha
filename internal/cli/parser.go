package cli

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/DonobanR/kagemusha/internal/model"
)

var (
	hexLower = regexp.MustCompile(`^[a-fA-F0-9]+$`)

	// Loose domain pattern: at least one dot, no spaces, no slashes,
	// not an IP. Actual DNS validity is not our job.
	domainPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$`)
)

// ParseIOC classifies a raw string into an IOC with its type.
// Returns an error if the string doesn't match any known type.
func ParseIOC(raw string) (model.IOC, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return model.IOC{}, fmt.Errorf("empty IOC value")
	}

	// Hashes: determined by length + hex content. Unambiguous.
	if hexLower.MatchString(raw) {
		switch len(raw) {
		case 32:
			return model.IOC{Value: strings.ToLower(raw), Type: model.TypeHashMD5}, nil
		case 40:
			return model.IOC{Value: strings.ToLower(raw), Type: model.TypeHashSHA1}, nil
		case 64:
			return model.IOC{Value: strings.ToLower(raw), Type: model.TypeHashSHA256}, nil
		}
	}

	// URLs: has scheme.
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if _, err := url.ParseRequestURI(raw); err == nil {
			return model.IOC{Value: raw, Type: model.TypeURL}, nil
		}
	}

	// IPs: v4 or v6.
	if ip := net.ParseIP(raw); ip != nil {
		if ip.To4() != nil {
			return model.IOC{Value: raw, Type: model.TypeIPv4}, nil
		}
		return model.IOC{Value: raw, Type: model.TypeIPv6}, nil
	}

	// Domains: has a dot, matches domain pattern.
	if strings.Contains(raw, ".") && domainPattern.MatchString(raw) {
		return model.IOC{Value: strings.ToLower(raw), Type: model.TypeDomain}, nil
	}

	return model.IOC{}, fmt.Errorf("unrecognized IOC type: %q", raw)
}
