package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
		wantErr bool
	}{
		{
			name: "valid config",
			content: `
database:
  driver: sqlite3
  path: ./test.db
slack:
  enabled: true
  webhook_url: "https://hooks.slack.com/test"
  channel: "#test"
`,
			want:    false,
			wantErr: false,
		},
		{
			name: "minimal config",
			content: `
database:
  driver: sqlite3
  path: ./test.db
`,
			want:    false,
			wantErr: false,
		},
		{
			name: "invalid yaml",
			content: `
database:
  driver: sqlite3
  path: ./test.db
  invalid: [unclosed array
`,
			want:    true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configPath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			_, err = LoadConfig(configPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestLoadConfigFromMissingFile(t *testing.T) {
	cfg, err := LoadConfig("nonexistent.yaml")

	// LoadConfig should return error for missing file
	if err == nil {
		t.Error("LoadConfig() should error on missing file")
		return
	}

	// When there's an error, config should be nil or default
	if cfg != nil {
		// Some implementations might return default config on error
		t.Log("LoadConfig() returned config despite error - this is acceptable")
	}
}

func TestDatabaseConfig_GetDSN(t *testing.T) {
	tests := []struct {
		name     string
		driver   string
		path     string
		host     string
		port     int
		username string
		password string
		database string
		sslmode  string
		want     string
	}{
		{
			name:   "sqlite3",
			driver: "sqlite3",
			path:   "./test.db",
			want:   "./test.db",
		},
		{
			name:     "postgres",
			driver:   "postgres",
			host:     "localhost",
			port:     5432,
			username: "user",
			password: "pass",
			database: "testdb",
			sslmode:  "disable",
			want:     "host=localhost port=5432 user=user password=pass dbname=testdb sslmode=disable",
		},
		{
			name:     "mysql",
			driver:   "mysql",
			host:     "localhost",
			port:     3306,
			username: "user",
			password: "pass",
			database: "testdb",
			want:     "user:pass@tcp(localhost:3306)/testdb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &DatabaseConfig{
				Driver:   tt.driver,
				Path:     tt.path,
				Host:     tt.host,
				Port:     tt.port,
				Username: tt.username,
				Password: tt.password,
				Name:     tt.database,
				SSLMode:  tt.sslmode,
			}

			got := db.GetDSN()
			if got != tt.want {
				t.Errorf("DatabaseConfig.GetDSN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	// Test getting default config
	config := GetConfig()
	if config == nil {
		t.Error("GetConfig() should return a config instance")
	}

	if config.Database.Driver == "" {
		t.Error("Default config should have database driver set")
	}
}

func TestGetMinimalConfig(t *testing.T) {
	// Create a temporary config file with minimal content
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "minimal.yaml")

	minimalContent := `
database:
  driver: sqlite3
  path: ./test.db
`

	err := os.WriteFile(configPath, []byte(minimalContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Errorf("LoadConfig() error = %v", err)
		return
	}

	if config.Database.Driver != "sqlite3" {
		t.Errorf("Expected driver 'sqlite3', got '%s'", config.Database.Driver)
	}
}
