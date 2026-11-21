package config_test

import (
	"os"
	"testing"

	"github.com/DonobanR/kagemusha/internal/config"
)

// isolateConfig changes to a temp dir and redirects APPDATA/HOME so tests
// don't pick up any real config.yaml (local or global).
func isolateConfig(t *testing.T) string {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })
	t.Setenv("APPDATA", tmp)
	t.Setenv("HOME", tmp)
	return tmp
}

func TestLoadFlagOverridesEnv(t *testing.T) {
	isolateConfig(t)
	t.Setenv("KAGEMUSHA_OTX_API_KEY", "env-otx")
	t.Setenv("KAGEMUSHA_ABUSECH_AUTH_KEY", "env-abuse")

	cfg, _, err := config.Load(config.Flags{
		OTXAPIKey:      "flag-otx",
		AbuseCHAuthKey: "flag-abuse",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OTXAPIKey != "flag-otx" {
		t.Errorf("OTXAPIKey = %q, want flag-otx", cfg.OTXAPIKey)
	}
	if cfg.AbuseCHAuthKey != "flag-abuse" {
		t.Errorf("AbuseCHAuthKey = %q, want flag-abuse", cfg.AbuseCHAuthKey)
	}
}

func TestLoadEnvWhenNoFlag(t *testing.T) {
	isolateConfig(t)
	t.Setenv("KAGEMUSHA_OTX_API_KEY", "env-otx")
	t.Setenv("KAGEMUSHA_ABUSECH_AUTH_KEY", "env-abuse")

	cfg, _, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OTXAPIKey != "env-otx" {
		t.Errorf("OTXAPIKey = %q, want env-otx", cfg.OTXAPIKey)
	}
	if cfg.AbuseCHAuthKey != "env-abuse" {
		t.Errorf("AbuseCHAuthKey = %q, want env-abuse", cfg.AbuseCHAuthKey)
	}
}

func TestLoadEmptyWhenNothingSet(t *testing.T) {
	isolateConfig(t)
	t.Setenv("KAGEMUSHA_OTX_API_KEY", "")
	t.Setenv("KAGEMUSHA_ABUSECH_AUTH_KEY", "")

	cfg, _, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OTXAPIKey != "" || cfg.AbuseCHAuthKey != "" {
		t.Errorf("expected empty config, got %+v", cfg)
	}
}

func TestLoadIndependentResolution(t *testing.T) {
	isolateConfig(t)
	t.Setenv("KAGEMUSHA_OTX_API_KEY", "env-otx")
	t.Setenv("KAGEMUSHA_ABUSECH_AUTH_KEY", "")

	cfg, _, err := config.Load(config.Flags{AbuseCHAuthKey: "flag-abuse"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OTXAPIKey != "env-otx" {
		t.Errorf("OTXAPIKey = %q, want env-otx", cfg.OTXAPIKey)
	}
	if cfg.AbuseCHAuthKey != "flag-abuse" {
		t.Errorf("AbuseCHAuthKey = %q, want flag-abuse", cfg.AbuseCHAuthKey)
	}
}

func TestLoadLocalConfigFile(t *testing.T) {
	isolateConfig(t)
	t.Setenv("KAGEMUSHA_OTX_API_KEY", "")
	t.Setenv("KAGEMUSHA_ABUSECH_AUTH_KEY", "")

	os.WriteFile("config.yaml", []byte("abusech_auth_key: local-key\n"), 0o600)

	cfg, _, err := config.Load(config.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AbuseCHAuthKey != "local-key" {
		t.Errorf("AbuseCHAuthKey = %q, want local-key", cfg.AbuseCHAuthKey)
	}
}

func TestMaskKey(t *testing.T) {
	tests := []struct {
		key, want string
	}{
		{"abcdef1234", "****1234"},
		{"1234", "****"},
		{"abc", "****"},
		{"", "****"},
	}
	for _, tc := range tests {
		if got := config.MaskKey(tc.key); got != tc.want {
			t.Errorf("MaskKey(%q) = %q, want %q", tc.key, got, tc.want)
		}
	}
}
