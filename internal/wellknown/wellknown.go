package wellknown

import "net"

// Kind distinguishes infrastructure IPs (benign) from non-routable
// addresses (outside the scope of external threat intelligence).
type Kind int

const (
	KindNone        Kind = iota
	KindInfra            // single-tenant infrastructure (public DNS resolvers)
	KindNotRoutable      // private, loopback, CGNAT, reserved, special
)

var infraIPs = map[string]string{
	"8.8.8.8":         "Google DNS",
	"8.8.4.4":         "Google DNS",
	"1.1.1.1":         "Cloudflare DNS",
	"1.0.0.1":         "Cloudflare DNS",
	"9.9.9.9":         "Quad9 DNS",
	"149.112.112.112":  "Quad9 DNS",
	"208.67.222.222":   "OpenDNS",
	"208.67.220.220":   "OpenDNS",
	"76.76.2.0":        "Control D DNS",
	"76.76.10.0":       "Control D DNS",
	"94.140.14.14":     "AdGuard DNS",
	"94.140.15.15":     "AdGuard DNS",
}

var specialIPs = map[string]string{
	"0.0.0.0":         "unspecified address",
	"255.255.255.255":  "broadcast address",
}

type privateRange struct {
	net   *net.IPNet
	label string
}

var privateRanges []privateRange

func init() {
	cidrs := []struct {
		cidr  string
		label string
	}{
		{"127.0.0.0/8", "loopback"},
		{"10.0.0.0/8", "private (RFC 1918)"},
		{"172.16.0.0/12", "private (RFC 1918)"},
		{"192.168.0.0/16", "private (RFC 1918)"},
		{"169.254.0.0/16", "link-local (RFC 3927)"},
		{"100.64.0.0/10", "CGNAT (RFC 6598)"},
		{"192.0.0.0/24", "IETF protocol (RFC 6890)"},
		{"192.0.2.0/24", "documentation (RFC 5737)"},
		{"198.51.100.0/24", "documentation (RFC 5737)"},
		{"203.0.113.0/24", "documentation (RFC 5737)"},
		{"198.18.0.0/15", "benchmarking (RFC 2544)"},
		{"240.0.0.0/4", "reserved (RFC 1112)"},
		// IPv6 reserved ranges
		{"::1/128", "loopback (IPv6)"},
		{"fe80::/10", "link-local (IPv6)"},
		{"fc00::/7", "unique local (IPv6 RFC 4193)"},
		{"2001:db8::/32", "documentation (IPv6 RFC 3849)"},
	}
	for _, c := range cidrs {
		_, ipNet, _ := net.ParseCIDR(c.cidr)
		privateRanges = append(privateRanges, privateRange{net: ipNet, label: c.label})
	}
}

// Check returns a human-readable label and the kind of match.
// KindInfra means known single-tenant infrastructure (emit benign).
// KindNotRoutable means private/reserved/special (emit unknown — outside
// scope of external threat intelligence).
// KindNone means no match (proceed with normal scan).
func Check(ip string) (label string, kind Kind) {
	if l, ok := infraIPs[ip]; ok {
		return l, KindInfra
	}
	if l, ok := specialIPs[ip]; ok {
		return l, KindNotRoutable
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", KindNone
	}
	for _, r := range privateRanges {
		if r.net.Contains(parsed) {
			return r.label, KindNotRoutable
		}
	}
	return "", KindNone
}
