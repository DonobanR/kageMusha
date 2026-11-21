package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config holds runtime configuration. Fields are populated from the
// three-level hierarchy: CLI flags > env vars > config file.
type Config struct {
	OTXAPIKey      string `yaml:"otx_api_key"`
	AbuseCHAuthKey string `yaml:"abusech_auth_key"`
}

// Flags holds CLI flag values passed to Load.
type Flags struct {
	OTXAPIKey      string
	AbuseCHAuthKey string
}

// Load resolves configuration from the hierarchy:
//
//  1. CLI flags (highest priority)
//  2. Environment variables
//  3. Local config file (./config.yaml)
//  4. Global config file (~/.config/kagemusha/config.yaml)
//
// Each key resolves independently through the hierarchy.
func Load(flags Flags) (Config, []string, error) {
	var warnings []string
	var fileCfg Config

	path := findConfigFile()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, warnings, fmt.Errorf("reading config: %w", err)
		}
		if w := checkPermissions(path); w != "" {
			warnings = append(warnings, w)
		}
		if err := yaml.Unmarshal(data, &fileCfg); err != nil {
			return Config{}, warnings, fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	cfg := Config{
		OTXAPIKey:      resolve(flags.OTXAPIKey, "KAGEMUSHA_OTX_API_KEY", fileCfg.OTXAPIKey),
		AbuseCHAuthKey: resolve(flags.AbuseCHAuthKey, "KAGEMUSHA_ABUSECH_AUTH_KEY", fileCfg.AbuseCHAuthKey),
	}

	return cfg, warnings, nil
}

// MaskKey returns a masked version of an API key for logging.
func MaskKey(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return "****" + key[len(key)-4:]
}

func resolve(flag, envVar, fileVal string) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return fileVal
}

func findConfigFile() string {
	if _, err := os.Stat("config.yaml"); err == nil {
		return "config.yaml"
	}
	global := globalConfigPath()
	if _, err := os.Stat(global); err == nil {
		return global
	}
	return ""
}

func globalConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "kagemusha", "config.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "kagemusha", "config.yaml")
}

func checkPermissions(path string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Sprintf("warning: %s has permissions %04o; recommended 0600 (like ~/.ssh/config)", path, perm)
	}
	return ""
}
