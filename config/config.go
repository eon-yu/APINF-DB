package config

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"oss-compliance-scanner/models"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Database     DatabaseConfig              `yaml:"database" mapstructure:"database"`
	Scanner      ScannerConfig               `yaml:"scanner" mapstructure:"scanner"`
	Policy       models.PolicyConfig         `yaml:"policy" mapstructure:"policy"`
	Notification models.NotificationSettings `yaml:"notification" mapstructure:"notification"`
	Logging      LoggingConfig               `yaml:"logging" mapstructure:"logging"`
}

// ScannerConfig represents scanner tool configuration
type ScannerConfig struct {
	SyftPath         string `yaml:"syft_path" mapstructure:"syft_path"`
	GrypePath        string `yaml:"grype_path" mapstructure:"grype_path"`
	TimeoutSeconds   int    `yaml:"timeout_seconds" mapstructure:"timeout_seconds"`
	MaxParallelScans int    `yaml:"max_parallel_scans" mapstructure:"max_parallel_scans"`
	TempDir          string `yaml:"temp_dir" mapstructure:"temp_dir"`
	CacheDir         string `yaml:"cache_dir" mapstructure:"cache_dir"`
}

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level      string `yaml:"level" mapstructure:"level"`
	Format     string `yaml:"format" mapstructure:"format"`
	Output     string `yaml:"output" mapstructure:"output"`
	File       string `yaml:"file" mapstructure:"file"`
	MaxSize    int    `yaml:"max_size" mapstructure:"max_size"`
	MaxBackups int    `yaml:"max_backups" mapstructure:"max_backups"`
	MaxAge     int    `yaml:"max_age" mapstructure:"max_age"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Driver   string `yaml:"driver" mapstructure:"driver"`
	Path     string `yaml:"path" mapstructure:"path"`
	Host     string `yaml:"host" mapstructure:"host"`
	Port     int    `yaml:"port" mapstructure:"port"`
	Username string `yaml:"username" mapstructure:"username"`
	Password string `yaml:"password" mapstructure:"password"`
	Name     string `yaml:"name" mapstructure:"name"`
	SSLMode  string `yaml:"ssl_mode" mapstructure:"ssl_mode"`
}

var config *Config = nil

func GetConfig() *Config {
	if config == nil {
		err := LoadConfig(os.Getenv("OSS_SCANNER_CONFIG_PATH"))
		if err != nil {
			log.Fatal("Failed to load config:", err)
			return getMinimalConfig()
		}
	}
	return config
}

// GetDSN returns the data source name for the database connection
func (dc *DatabaseConfig) GetDSN() string {
	switch dc.Driver {
	case "sqlite3":
		return dc.Path
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			dc.Host, dc.Port, dc.Username, dc.Password, dc.Name, dc.SSLMode)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			dc.Username, dc.Password, dc.Host, dc.Port, dc.Name)
	default:
		return dc.Path // fallback to path for SQLite
	}
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) error {
	// Set default values
	setDefaults()

	// Load from file if specified
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		// Look for config file in standard locations
		viper.SetConfigName(".oss-compliance-scanner")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME")
		viper.AddConfigPath("/etc/oss-compliance-scanner")
	}

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults and environment variables
	}

	// Override with environment variables
	viper.SetEnvPrefix("OSS_SCANNER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Unmarshal config
	loadConfig := &Config{}
	if err := viper.Unmarshal(loadConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate and set defaults for computed values
	if err := validateAndSetDefaults(loadConfig); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	config = loadConfig
	return nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Database defaults
	viper.SetDefault("database.driver", "sqlite3")
	viper.SetDefault("database.path", "./oss_scan.db")

	// Scanner defaults
	viper.SetDefault("scanner.syft_path", "syft")
	viper.SetDefault("scanner.grype_path", "grype")
	viper.SetDefault("scanner.timeout_seconds", 300)
	viper.SetDefault("scanner.max_parallel_scans", 3)
	viper.SetDefault("scanner.temp_dir", "/tmp/oss-scanner")
	viper.SetDefault("scanner.cache_dir", "$HOME/.cache/oss-scanner")

	// Policy defaults
	viper.SetDefault("policy.global_settings.enable_license_check", true)
	viper.SetDefault("policy.global_settings.enable_vulnerability_check", true)
	viper.SetDefault("policy.global_settings.scan_timeout", 30)
	viper.SetDefault("policy.global_settings.max_parallel_scans", 3)

	// Notification defaults
	viper.SetDefault("notification.notify_on_violation", true)
	viper.SetDefault("notification.notify_on_resolution", false)
	viper.SetDefault("notification.min_severity_level", "High")
	viper.SetDefault("notification.notification_batching", true)
	viper.SetDefault("notification.batching_interval", 60)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "text")
	viper.SetDefault("logging.output", "stdout")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 3)
	viper.SetDefault("logging.max_age", 30)
}

// validateAndSetDefaults validates configuration and sets computed defaults
func validateAndSetDefaults(config *Config) error {
	// Expand environment variables in paths
	config.Database.Path = os.ExpandEnv(config.Database.Path)
	config.Scanner.TempDir = os.ExpandEnv(config.Scanner.TempDir)
	config.Scanner.CacheDir = os.ExpandEnv(config.Scanner.CacheDir)

	// Ensure database directory exists
	if config.Database.Driver == "sqlite3" {
		dbDir := filepath.Dir(config.Database.Path)
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Ensure temp and cache directories exist
	if err := os.MkdirAll(config.Scanner.TempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	if err := os.MkdirAll(config.Scanner.CacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Validate scanner tool paths
	if err := validateToolPath(config.Scanner.SyftPath, "syft"); err != nil {
		return err
	}
	if err := validateToolPath(config.Scanner.GrypePath, "grype"); err != nil {
		return err
	}

	// Set default license policies if none specified
	if len(config.Policy.LicensePolicies) == 0 {
		config.Policy.LicensePolicies = getDefaultLicensePolicies()
	}

	// Set default vulnerability policies if none specified
	if len(config.Policy.VulnerabilityPolicies) == 0 {
		config.Policy.VulnerabilityPolicies = getDefaultVulnerabilityPolicies()
	}

	return nil
}

// validateToolPath validates that a scanner tool is available
func validateToolPath(toolPath, toolName string) error {
	// If absolute path, check if file exists
	if filepath.IsAbs(toolPath) {
		if _, err := os.Stat(toolPath); err != nil {
			return fmt.Errorf("%s tool not found at %s: %w", toolName, toolPath, err)
		}
		return nil
	}

	// If relative path, check if it's in PATH
	if _, err := exec.LookPath(toolPath); err != nil {
		return fmt.Errorf("%s tool not found in PATH (%s): %w", toolName, toolPath, err)
	}

	return nil
}

// getMinimalConfig returns a minimal configuration with defaults
func getMinimalConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Driver: "sqlite3",
			Path:   "./oss_scan.db",
		},
		Scanner: ScannerConfig{
			SyftPath:         "syft",
			GrypePath:        "grype",
			TimeoutSeconds:   300,
			MaxParallelScans: 3,
			TempDir:          "/tmp/oss-scanner",
			CacheDir:         os.ExpandEnv("$HOME/.cache/oss-scanner"),
		},
		Policy: models.PolicyConfig{
			LicensePolicies:       getDefaultLicensePolicies(),
			VulnerabilityPolicies: getDefaultVulnerabilityPolicies(),
			GlobalSettings: models.GlobalPolicySettings{
				EnableLicenseCheck:       true,
				EnableVulnerabilityCheck: true,
				ScanTimeout:              30,
				MaxParallelScans:         3,
			},
		},
		Notification: models.NotificationSettings{
			NotifyOnViolation:    true,
			NotifyOnResolution:   false,
			MinSeverityLevel:     "High",
			NotificationBatching: true,
			BatchingInterval:     60,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			Output:     "stdout",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     30,
		},
	}
}

// getDefaultLicensePolicies returns default license policies
func getDefaultLicensePolicies() []models.LicensePolicy {
	return []models.LicensePolicy{
		{
			LicenseName: "GPL-3.0",
			Action:      models.PolicyActionBlock,
			Reason:      "Copyleft license - requires source code disclosure",
			IsActive:    true,
		},
		{
			LicenseName: "GPL-2.0",
			Action:      models.PolicyActionBlock,
			Reason:      "Copyleft license - requires source code disclosure",
			IsActive:    true,
		},
		{
			LicenseName: "AGPL-3.0",
			Action:      models.PolicyActionBlock,
			Reason:      "Strong copyleft license - requires source code disclosure",
			IsActive:    true,
		},
		{
			LicenseName: "MIT",
			Action:      models.PolicyActionAllow,
			Reason:      "Permissive license",
			IsActive:    true,
		},
		{
			LicenseName: "Apache-2.0",
			Action:      models.PolicyActionAllow,
			Reason:      "Permissive license",
			IsActive:    true,
		},
		{
			LicenseName: "BSD-3-Clause",
			Action:      models.PolicyActionAllow,
			Reason:      "Permissive license",
			IsActive:    true,
		},
		{
			LicenseName: "ISC",
			Action:      models.PolicyActionAllow,
			Reason:      "Permissive license",
			IsActive:    true,
		},
		{
			LicenseName: "Unknown",
			Action:      models.PolicyActionWarn,
			Reason:      "License information not available",
			IsActive:    true,
		},
	}
}

// getDefaultVulnerabilityPolicies returns default vulnerability policies
func getDefaultVulnerabilityPolicies() []models.VulnerabilityPolicy {
	return []models.VulnerabilityPolicy{
		{
			MinSeverityLevel:   "Critical",
			MaxCVSSScore:       10.0,
			Action:             models.PolicyActionFail,
			IgnoreFixAvailable: false,
			GracePeriodDays:    0,
			IsActive:           true,
		},
		{
			MinSeverityLevel:   "High",
			MaxCVSSScore:       8.9,
			Action:             models.PolicyActionWarn,
			IgnoreFixAvailable: false,
			GracePeriodDays:    7,
			IsActive:           true,
		},
		{
			MinSeverityLevel:   "Medium",
			MaxCVSSScore:       6.9,
			Action:             models.PolicyActionWarn,
			IgnoreFixAvailable: true,
			GracePeriodDays:    30,
			IsActive:           true,
		},
	}
}

// SaveConfig saves the current configuration to a file
func SaveConfig(config *Config, filePath string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GenerateDefaultConfig creates a default configuration file
func GenerateDefaultConfig(filePath string) error {
	config := getMinimalConfig()
	return SaveConfig(config, filePath)
}
