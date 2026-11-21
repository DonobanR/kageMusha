package cli_test

import (
	"testing"

	"github.com/DonobanR/kagemusha/internal/cli"
	"github.com/DonobanR/kagemusha/internal/model"
)

func TestParseIOC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    model.IOCType
		wantVal string
		wantErr bool
	}{
		// Hashes
		{"md5", "d41d8cd98f00b204e9800998ecf8427e", model.TypeHashMD5, "d41d8cd98f00b204e9800998ecf8427e", false},
		{"md5 uppercase", "D41D8CD98F00B204E9800998ECF8427E", model.TypeHashMD5, "d41d8cd98f00b204e9800998ecf8427e", false},
		{"sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", model.TypeHashSHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", false},
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", model.TypeHashSHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"hex wrong length", "abcdef1234", "", "", true},

		// URLs
		{"http url", "http://evil.com/payload.exe", model.TypeURL, "http://evil.com/payload.exe", false},
		{"https url", "https://bad.example.org/c2", model.TypeURL, "https://bad.example.org/c2", false},

		// IPs
		{"ipv4", "8.8.8.8", model.TypeIPv4, "8.8.8.8", false},
		{"ipv4 private", "192.168.1.1", model.TypeIPv4, "192.168.1.1", false},
		{"ipv6", "2606:4700:4700::1111", model.TypeIPv6, "2606:4700:4700::1111", false},
		{"ipv6 loopback", "::1", model.TypeIPv6, "::1", false},

		// Domains
		{"domain", "evil.com", model.TypeDomain, "evil.com", false},
		{"subdomain", "c2.evil.example.org", model.TypeDomain, "c2.evil.example.org", false},
		{"domain uppercase", "Evil.COM", model.TypeDomain, "evil.com", false},

		// Invalid
		{"empty", "", "", "", true},
		{"spaces", "  ", "", "", true},
		{"no dot single word", "localhost", "", "", true},
		{"bare number", "12345", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cli.ParseIOC(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseIOC(%q) = %v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIOC(%q) error: %v", tc.input, err)
			}
			if got.Type != tc.want {
				t.Errorf("type = %v, want %v", got.Type, tc.want)
			}
			if got.Value != tc.wantVal {
				t.Errorf("value = %q, want %q", got.Value, tc.wantVal)
			}
		})
	}
}
