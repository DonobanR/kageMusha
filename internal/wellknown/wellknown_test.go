package wellknown

import "testing"

func TestInfrastructureIPs(t *testing.T) {
	cases := []struct {
		ip    string
		label string
	}{
		{"8.8.8.8", "Google DNS"},
		{"8.8.4.4", "Google DNS"},
		{"1.1.1.1", "Cloudflare DNS"},
		{"1.0.0.1", "Cloudflare DNS"},
		{"9.9.9.9", "Quad9 DNS"},
		{"208.67.222.222", "OpenDNS"},
	}
	for _, tc := range cases {
		label, kind := Check(tc.ip)
		if kind != KindInfra {
			t.Errorf("Check(%q) kind=%v, want KindInfra", tc.ip, kind)
		}
		if label != tc.label {
			t.Errorf("Check(%q) label=%q, want %q", tc.ip, label, tc.label)
		}
	}
}

func TestSpecialAddresses(t *testing.T) {
	cases := []struct {
		ip    string
		label string
	}{
		{"0.0.0.0", "unspecified address"},
		{"255.255.255.255", "broadcast address"},
	}
	for _, tc := range cases {
		label, kind := Check(tc.ip)
		if kind != KindNotRoutable {
			t.Errorf("Check(%q) kind=%v, want KindNotRoutable", tc.ip, kind)
		}
		if label != tc.label {
			t.Errorf("Check(%q) label=%q, want %q", tc.ip, label, tc.label)
		}
	}
}

func TestPrivateRanges(t *testing.T) {
	cases := []struct {
		ip    string
		label string
	}{
		{"127.0.0.1", "loopback"},
		{"127.0.1.5", "loopback"},
		{"10.0.0.1", "private (RFC 1918)"},
		{"10.255.255.255", "private (RFC 1918)"},
		{"172.16.0.1", "private (RFC 1918)"},
		{"172.31.255.255", "private (RFC 1918)"},
		{"192.168.0.1", "private (RFC 1918)"},
		{"192.168.100.100", "private (RFC 1918)"},
		{"169.254.1.1", "link-local (RFC 3927)"},
		{"100.64.0.1", "CGNAT (RFC 6598)"},
		{"192.0.2.1", "documentation (RFC 5737)"},
		{"198.51.100.1", "documentation (RFC 5737)"},
		{"203.0.113.1", "documentation (RFC 5737)"},
	}
	for _, tc := range cases {
		label, kind := Check(tc.ip)
		if kind != KindNotRoutable {
			t.Errorf("Check(%q) kind=%v, want KindNotRoutable", tc.ip, kind)
		}
		if label != tc.label {
			t.Errorf("Check(%q) label=%q, want %q", tc.ip, label, tc.label)
		}
	}
}

func TestPublicIPsPassThrough(t *testing.T) {
	ips := []string{
		"162.243.103.246",
		"45.155.205.233",
		"185.220.101.1",
		"104.16.132.229",
		"3.5.0.1",
	}
	for _, ip := range ips {
		_, kind := Check(ip)
		if kind != KindNone {
			t.Errorf("Check(%q) kind=%v, want KindNone (public IP should pass through)", ip, kind)
		}
	}
}

func TestNonIPPassesThrough(t *testing.T) {
	_, kind := Check("not-an-ip")
	if kind != KindNone {
		t.Error("non-IP string should return KindNone")
	}
}
