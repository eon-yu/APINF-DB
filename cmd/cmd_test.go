package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestEnvironment sets up a clean test environment
func setupTestEnvironment(t *testing.T) func() {
	// Save current environment
	originalArgs := os.Args
	originalEnv := os.Environ()

	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "cmd_test_*")
	require.NoError(t, err)

	// Reset viper configuration
	viper.Reset()

	cleanup := func() {
		// Restore environment
		os.Args = originalArgs
		for _, env := range originalEnv {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				os.Setenv(parts[0], parts[1])
			}
		}
		// Clean up temp directory
		os.RemoveAll(tempDir)
		// Reset viper
		viper.Reset()
	}

	return cleanup
}

// createTestRepository creates a test repository structure
func createTestRepository(t *testing.T) (string, func()) {
	tempDir, err := os.MkdirTemp("", "test_repo_*")
	require.NoError(t, err)

	// Create basic repository structure
	err = os.MkdirAll(filepath.Join(tempDir, "frontend"), 0755)
	require.NoError(t, err)

	err = os.MkdirAll(filepath.Join(tempDir, "backend"), 0755)
	require.NoError(t, err)

	// Create package.json files
	frontendPackageJSON := `{
  "name": "frontend-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.0.0",
    "lodash": "^4.17.21"
  }
}`
	err = os.WriteFile(filepath.Join(tempDir, "frontend", "package.json"), []byte(frontendPackageJSON), 0644)
	require.NoError(t, err)

	backendGoMod := `module backend-app

go 1.19

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/stretchr/testify v1.8.4
)
`
	err = os.WriteFile(filepath.Join(tempDir, "backend", "go.mod"), []byte(backendGoMod), 0644)
	require.NoError(t, err)

	// Create root package.json with workspaces
	rootPackageJSON := `{
  "name": "monorepo",
  "version": "1.0.0",
  "workspaces": [
    "frontend",
    "backend"
  ]
}`
	err = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(rootPackageJSON), 0644)
	require.NoError(t, err)

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return tempDir, cleanup
}

func TestGetVersionString(t *testing.T) {
	// Test with empty values
	appVersion = ""
	appCommit = ""
	appDate = ""

	version := getVersionString()
	assert.Contains(t, version, "unknown")

	// Test with actual values
	appVersion = "1.0.0"
	appCommit = "abc123"
	appDate = "2023-01-01"

	version = getVersionString()
	assert.Contains(t, version, "1.0.0")
	assert.Contains(t, version, "abc123")
	assert.Contains(t, version, "2023-01-01")

	// Reset for other tests
	appVersion = ""
	appCommit = ""
	appDate = ""
}

func TestExecute(t *testing.T) {
	cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Test with version, commit, and date
	err := Execute("1.0.0", "test-commit", "2023-01-01")
	// We expect this to execute successfully but return an error because no subcommand is provided
	// The error is expected behavior for cobra when no subcommand is given
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command")
}

func TestInitConfig(t *testing.T) {
	cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create temporary config file
	tempDir, err := os.MkdirTemp("", "config_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configContent := `
database:
  driver: sqlite3
  dsn: test.db
slack:
  webhook_url: https://hooks.slack.com/test
  channel: "#alerts"
`
	configFile := filepath.Join(tempDir, ".oss-compliance-scanner.yaml")
	err = os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Set config file path
	cfgFile = configFile

	// Call initConfig
	initConfig()

	// Verify config was loaded
	assert.Equal(t, "sqlite3", viper.GetString("database.driver"))
	assert.Equal(t, "test.db", viper.GetString("database.dsn"))
	assert.Equal(t, "https://hooks.slack.com/test", viper.GetString("slack.webhook_url"))
}

func TestInitConfig_NoConfigFile(t *testing.T) {
	cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Set non-existent config file
	cfgFile = ""

	// Call initConfig (should not fail)
	assert.NotPanics(t, func() {
		initConfig()
	})
}

func TestDetermineScanTargets_SpecificModule(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	ctx := &ScanContext{
		RepoPath:   repoPath,
		ModulePath: "frontend",
	}

	targets := determineScanTargets(ctx)
	assert.Len(t, targets, 1)
	assert.Contains(t, targets[0], "frontend")
}

func TestDetermineScanTargets_AutoDiscover(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	ctx := &ScanContext{
		RepoPath:   repoPath,
		ModulePath: "", // Auto-discover
	}

	targets := determineScanTargets(ctx)
	assert.Greater(t, len(targets), 0)

	// Should find both frontend and backend
	var foundFrontend, foundBackend bool
	for _, target := range targets {
		if strings.Contains(target, "frontend") {
			foundFrontend = true
		}
		if strings.Contains(target, "backend") {
			foundBackend = true
		}
	}
	assert.True(t, foundFrontend, "Should find frontend module")
	assert.True(t, foundBackend, "Should find backend module")
}

func TestAutoDiscoverTargets(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	targets := autoDiscoverTargets(repoPath)
	assert.Greater(t, len(targets), 0)

	// Should find package.json and go.mod files
	var foundPackageJSON, foundGoMod bool
	for _, target := range targets {
		if strings.Contains(target, "package.json") {
			foundPackageJSON = true
		}
		if strings.Contains(target, "go.mod") {
			foundGoMod = true
		}
	}
	assert.True(t, foundPackageJSON, "Should find package.json files")
	assert.True(t, foundGoMod, "Should find go.mod files")
}

func TestDiscoverWorkspaceTargets(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	targets := discoverWorkspaceTargets(repoPath)
	assert.Greater(t, len(targets), 0)

	// Should find workspace targets
	var foundFrontend, foundBackend bool
	for _, target := range targets {
		if strings.Contains(target, "frontend") {
			foundFrontend = true
		}
		if strings.Contains(target, "backend") {
			foundBackend = true
		}
	}
	assert.True(t, foundFrontend, "Should find frontend workspace")
	assert.True(t, foundBackend, "Should find backend workspace")
}

func TestParsePackageJsonWorkspaces(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	packagePath := filepath.Join(repoPath, "package.json")
	workspaces := parsePackageJsonWorkspaces(packagePath)

	assert.Len(t, workspaces, 2)
	assert.Contains(t, workspaces, "frontend")
	assert.Contains(t, workspaces, "backend")
}

func TestParsePackageJsonWorkspaces_NoFile(t *testing.T) {
	workspaces := parsePackageJsonWorkspaces("/non/existent/package.json")
	assert.Empty(t, workspaces)
}

func TestParsePackageJsonWorkspaces_InvalidJSON(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "invalid_json_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	invalidJSON := `{ invalid json content`
	packagePath := filepath.Join(tempDir, "package.json")
	err = os.WriteFile(packagePath, []byte(invalidJSON), 0644)
	require.NoError(t, err)

	workspaces := parsePackageJsonWorkspaces(packagePath)
	assert.Empty(t, workspaces)
}

func TestSortTargetsByPriority(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	targets := []string{
		filepath.Join(repoPath, "frontend", "package.json"),
		filepath.Join(repoPath, "backend", "go.mod"),
		filepath.Join(repoPath, "package.json"), // Root should have priority
	}

	sorted := sortTargetsByPriority(repoPath, targets)

	// Root package.json should be first (highest priority)
	assert.True(t, strings.HasSuffix(sorted[0], "package.json"))
	assert.False(t, strings.Contains(sorted[0], "frontend"))
}

func TestRemoveDuplicates(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	result := removeDuplicates(input)

	assert.Len(t, result, 4)
	assert.Contains(t, result, "a")
	assert.Contains(t, result, "b")
	assert.Contains(t, result, "c")
	assert.Contains(t, result, "d")

	// Check that order is preserved for first occurrence
	assert.Equal(t, "a", result[0])
	assert.Equal(t, "b", result[1])
	assert.Equal(t, "c", result[2])
	assert.Equal(t, "d", result[3])
}

func TestRemoveDuplicates_EmptySlice(t *testing.T) {
	result := removeDuplicates([]string{})
	assert.Empty(t, result)
}

func TestRemoveDuplicates_NoDuplicates(t *testing.T) {
	input := []string{"a", "b", "c"}
	result := removeDuplicates(input)

	assert.Len(t, result, 3)
	assert.Equal(t, input, result)
}

func TestScanContext_Validation(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	// Valid context
	ctx := &ScanContext{
		RepoPath:     repoPath,
		ModulePath:   "",
		OutputFormat: "table",
		SkipSBOM:     false,
		SkipVuln:     false,
		Notify:       true,
		Verbose:      false,
	}

	assert.NotNil(t, ctx)
	assert.Equal(t, repoPath, ctx.RepoPath)
	assert.Equal(t, "table", ctx.OutputFormat)
	assert.False(t, ctx.SkipSBOM)
	assert.True(t, ctx.Notify)
}

func TestScanContext_OutputFormats(t *testing.T) {
	validFormats := []string{"table", "json", "yaml"}

	for _, format := range validFormats {
		ctx := &ScanContext{
			OutputFormat: format,
		}
		assert.Equal(t, format, ctx.OutputFormat)
	}
}

func TestScanContext_Flags(t *testing.T) {
	// Test various flag combinations
	testCases := []struct {
		name     string
		skipSBOM bool
		skipVuln bool
		notify   bool
		verbose  bool
	}{
		{"default", false, false, true, false},
		{"skip_sbom", true, false, true, false},
		{"skip_vuln", false, true, true, false},
		{"no_notify", false, false, false, false},
		{"verbose", false, false, true, true},
		{"all_skip", true, true, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &ScanContext{
				SkipSBOM: tc.skipSBOM,
				SkipVuln: tc.skipVuln,
				Notify:   tc.notify,
				Verbose:  tc.verbose,
			}

			assert.Equal(t, tc.skipSBOM, ctx.SkipSBOM)
			assert.Equal(t, tc.skipVuln, ctx.SkipVuln)
			assert.Equal(t, tc.notify, ctx.Notify)
			assert.Equal(t, tc.verbose, ctx.Verbose)
		})
	}
}

// Test package discovery for different languages
func TestLanguageSpecificDiscovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lang_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create various language-specific files
	files := map[string]string{
		"package.json":     `{"name": "node-app", "dependencies": {}}`,
		"go.mod":           `module test-app\ngo 1.19`,
		"requirements.txt": `requests==2.28.0\nflask==2.0.0`,
		"pom.xml":          `<project><modelVersion>4.0.0</modelVersion></project>`,
		"Gemfile":          `source 'https://rubygems.org'\ngem 'rails'`,
	}

	for filename, content := range files {
		err = os.WriteFile(filepath.Join(tempDir, filename), []byte(content), 0644)
		require.NoError(t, err)
	}

	targets := autoDiscoverTargets(tempDir)

	// Should find all language-specific files
	assert.Greater(t, len(targets), 0)

	foundFiles := make(map[string]bool)
	for _, target := range targets {
		base := filepath.Base(target)
		foundFiles[base] = true
	}

	assert.True(t, foundFiles["package.json"], "Should find package.json")
	assert.True(t, foundFiles["go.mod"], "Should find go.mod")
	assert.True(t, foundFiles["requirements.txt"], "Should find requirements.txt")
	assert.True(t, foundFiles["pom.xml"], "Should find pom.xml")
	assert.True(t, foundFiles["Gemfile"], "Should find Gemfile")
}

func TestNestedDirectoryDiscovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nested_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create nested structure
	nestedDirs := []string{
		"services/auth",
		"services/api",
		"libs/common",
		"apps/frontend",
		"apps/backend",
	}

	for _, dir := range nestedDirs {
		err = os.MkdirAll(filepath.Join(tempDir, dir), 0755)
		require.NoError(t, err)

		// Add package.json to each
		packageJSON := `{"name": "` + strings.ReplaceAll(dir, "/", "-") + `"}`
		err = os.WriteFile(filepath.Join(tempDir, dir, "package.json"), []byte(packageJSON), 0644)
		require.NoError(t, err)
	}

	targets := autoDiscoverTargets(tempDir)
	assert.GreaterOrEqual(t, len(targets), len(nestedDirs))

	// Should find all nested package.json files
	for _, dir := range nestedDirs {
		found := false
		for _, target := range targets {
			if strings.Contains(target, dir) {
				found = true
				break
			}
		}
		assert.True(t, found, "Should find package.json in %s", dir)
	}
}

func TestEmptyDirectoryHandling(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "empty_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create empty subdirectories
	err = os.MkdirAll(filepath.Join(tempDir, "empty1"), 0755)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(tempDir, "empty2"), 0755)
	require.NoError(t, err)

	targets := autoDiscoverTargets(tempDir)

	// Should handle empty directories gracefully
	assert.NotNil(t, targets)
	// Should not find any targets in empty directories
	for _, target := range targets {
		assert.False(t, strings.Contains(target, "empty1"))
		assert.False(t, strings.Contains(target, "empty2"))
	}
}

func TestInvalidPathHandling(t *testing.T) {
	// Test with non-existent path
	targets := autoDiscoverTargets("/non/existent/path")
	assert.Empty(t, targets)

	targets = discoverWorkspaceTargets("/non/existent/path")
	assert.Empty(t, targets)
}

func TestConcurrentTargetProcessing(t *testing.T) {
	repoPath, cleanup := createTestRepository(t)
	defer cleanup()

	ctx := &ScanContext{
		RepoPath:   repoPath,
		ModulePath: "",
		Verbose:    true,
	}

	targets := determineScanTargets(ctx)
	assert.Greater(t, len(targets), 1, "Need multiple targets for concurrency test")

	// Test that targets can be processed (this tests the structure,
	// actual processing would require full initialization)
	assert.NotNil(t, targets)
	assert.Greater(t, len(targets), 0)
}
