package scanner

import (
	"context"
	"testing"
	"time"

	"oss-compliance-scanner/models"
	"strings"

	"github.com/stretchr/testify/assert"
)

func TestNewSyftScanner(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)

	if scanner == nil {
		t.Error("NewSyftScanner should return a valid scanner")
	}

	if scanner.syftPath != "syft" {
		t.Errorf("Expected syftPath 'syft', got %s", scanner.syftPath)
	}

	if scanner.timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", scanner.timeout)
	}
}

func TestDefaultScanOptions(t *testing.T) {
	options := DefaultScanOptions()

	if options == nil {
		t.Fatal("DefaultScanOptions should return valid options")
	}

	if options.OutputFormat != "json" {
		t.Errorf("Expected OutputFormat 'json', got %s", options.OutputFormat)
	}

	if options.Scope != "squashed" {
		t.Errorf("Expected Scope 'squashed', got %s", options.Scope)
	}
}

func TestSyftScanner_GenerateSBOM_InvalidPath(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)
	ctx := context.Background()
	options := DefaultScanOptions()

	// Test with non-existent directory
	_, err := scanner.GenerateSBOM(ctx, "/non/existent/path", options)
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
}

func TestSyftScanner_GenerateSBOM_NilOptions(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)
	ctx := context.Background()

	// Test with nil options (should use defaults)
	_, err := scanner.GenerateSBOM(ctx, "/tmp", nil)
	// This will likely fail due to syft not being available, but should not panic
	if err == nil {
		t.Log("GenerateSBOM completed without error (syft must be installed)")
	} else {
		t.Logf("GenerateSBOM failed as expected: %v", err)
	}
}

func TestSyftScanner_GetVersion(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)
	ctx := context.Background()

	version, err := scanner.GetVersion(ctx)

	// This will likely fail if syft is not installed, which is expected
	if err != nil {
		t.Logf("GetVersion failed as expected (syft not installed): %v", err)
	} else {
		if version == "" {
			t.Error("GetVersion should return a non-empty string when successful")
		} else {
			t.Logf("Syft version: %s", version)
		}
	}
}

func TestSyftScanner_ValidateInstallation(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)
	ctx := context.Background()

	err := scanner.ValidateInstallation(ctx)

	// This will likely fail if syft is not installed
	if err != nil {
		t.Logf("ValidateInstallation failed as expected: %v", err)
	} else {
		t.Log("Syft installation validated successfully")
	}
}

func TestSyftScanner_ParseSBOMToComponents(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)

	// Create a test SBOM with valid JSON
	sbom := &models.SBOM{
		ID: 1,
		RawSBOM: `{
			"schema": {"version": "1.0", "url": "test"},
			"distro": {"name": "test", "version": "1.0"},
			"source": {"type": "directory", "target": "/test"},
			"artifacts": [
				{
					"id": "test-1",
					"name": "express",
					"version": "4.17.1",
					"type": "npm",
					"purl": "pkg:npm/express@4.17.1",
					"language": "javascript",
					"licenses": ["MIT"],
					"locations": [{"path": "/app/package.json"}],
					"metadata": {"description": "Fast web framework"},
					"cpes": [{"cpe": "cpe:2.3:a:express:express:4.17.1:*:*:*:*:*:*:*"}]
				}
			]
		}`,
	}

	components, err := scanner.ParseSBOMToComponents(sbom)
	if err != nil {
		t.Errorf("ParseSBOMToComponents() error = %v", err)
	}

	if len(components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(components))
	}

	if len(components) > 0 {
		component := components[0]
		if component.Name != "express" {
			t.Errorf("Expected component name 'express', got %s", component.Name)
		}
		if component.Version != "4.17.1" {
			t.Errorf("Expected component version '4.17.1', got %s", component.Version)
		}
		if component.Language != "javascript" {
			t.Errorf("Expected component language 'javascript', got %s", component.Language)
		}
	}
}

func TestSyftScanner_ParseSBOMToComponents_InvalidJSON(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)

	sbom := &models.SBOM{
		ID:      1,
		RawSBOM: `invalid json`,
	}

	_, err := scanner.ParseSBOMToComponents(sbom)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestExtractRepoName(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple path",
			path:     "/home/user/project",
			expected: "project",
		},
		{
			name:     "root path",
			path:     "/",
			expected: "/",
		},
		{
			name:     "nested path",
			path:     "/home/user/workspace/my-project",
			expected: "my-project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRepoName(tt.path)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestExtractModulePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "root directory",
			path:     "/project",
			expected: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractModulePath(tt.path)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetCatalogersForEcosystem(t *testing.T) {
	tests := []struct {
		ecosystem string
		hasResult bool
	}{
		{
			ecosystem: "npm",
			hasResult: true,
		},
		{
			ecosystem: "go",
			hasResult: true,
		},
		{
			ecosystem: "python",
			hasResult: true,
		},
		{
			ecosystem: "maven",
			hasResult: true,
		},
		{
			ecosystem: "unknown",
			hasResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			result := getCatalogersForEcosystem(tt.ecosystem)

			if tt.hasResult && len(result) == 0 {
				t.Errorf("Expected catalogers for %s, got empty result", tt.ecosystem)
			}

			if !tt.hasResult && len(result) > 0 {
				t.Errorf("Expected no catalogers for %s, got %v", tt.ecosystem, result)
			}
		})
	}
}

func TestScanOptions_CustomValues(t *testing.T) {
	options := &ScanOptions{
		OutputFormat: "spdx-json",
		Scope:        "all-layers",
		Platform:     "linux/amd64",
		Catalogers:   []string{"java-pom", "java-gradle"},
		Quiet:        true,
		Verbose:      false,
	}

	if options.OutputFormat != "spdx-json" {
		t.Errorf("Expected OutputFormat 'spdx-json', got %s", options.OutputFormat)
	}

	if options.Scope != "all-layers" {
		t.Errorf("Expected Scope 'all-layers', got %s", options.Scope)
	}

	if len(options.Catalogers) != 2 {
		t.Errorf("Expected 2 catalogers, got %d", len(options.Catalogers))
	}

	if !options.Quiet {
		t.Error("Expected Quiet to be true")
	}
}

func TestSyftScanner_ContextCancellation(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 60)

	// Create a context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := scanner.GenerateSBOM(ctx, "/tmp", DefaultScanOptions())
	if err == nil {
		t.Error("Expected error when context is cancelled")
	}
}

func TestSyftScanner_Timeout(t *testing.T) {
	scanner := NewSyftScanner("syft", "/tmp", "/cache", 1) // 1 second timeout

	ctx := context.Background()

	_, err := scanner.GenerateSBOM(ctx, "/tmp", DefaultScanOptions())
	// This may or may not timeout depending on system performance
	// but should not panic
	if err != nil {
		t.Logf("GenerateSBOM failed (expected for timeout test): %v", err)
	}
}

// Tests for grype.go

func TestNewGrypeScanner(t *testing.T) {
	scanner := NewGrypeScanner("/usr/local/bin/grype", "/tmp", "/tmp/cache", 60)
	assert.NotNil(t, scanner)
	assert.Equal(t, "/usr/local/bin/grype", scanner.grypePath)
	assert.Equal(t, "/tmp", scanner.tempDir)
	assert.Equal(t, "/tmp/cache", scanner.cacheDir)
	assert.Equal(t, 60*time.Second, scanner.timeout)
}

func TestDefaultVulnScanOptions(t *testing.T) {
	options := DefaultVulnScanOptions()
	assert.NotNil(t, options)
	assert.Equal(t, "json", options.OutputFormat)
	assert.Equal(t, "squashed", options.Scope)
	assert.Empty(t, options.Platform)
	assert.Empty(t, options.FailOn)
	assert.False(t, options.OnlyFixed)
	assert.Nil(t, options.IgnoreStates)
	assert.False(t, options.Quiet)
	assert.False(t, options.Verbose)
}

func TestVulnScanOptions_CustomValues(t *testing.T) {
	options := &VulnScanOptions{
		OutputFormat: "sarif",
		Scope:        "all-layers",
		Platform:     "linux/amd64",
		FailOn:       "high",
		OnlyFixed:    true,
		IgnoreStates: []string{"wont-fix", "unknown"},
		Quiet:        true,
		Verbose:      false,
	}

	assert.Equal(t, "sarif", options.OutputFormat)
	assert.Equal(t, "all-layers", options.Scope)
	assert.Equal(t, "linux/amd64", options.Platform)
	assert.Equal(t, "high", options.FailOn)
	assert.True(t, options.OnlyFixed)
	assert.Len(t, options.IgnoreStates, 2)
	assert.Contains(t, options.IgnoreStates, "wont-fix")
	assert.True(t, options.Quiet)
	assert.False(t, options.Verbose)
}

func TestGrypeScanner_GetVersion(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)
	ctx := context.Background()

	version, err := scanner.GetVersion(ctx)
	if err != nil {
		t.Logf("Grype not installed or not in PATH: %v", err)
		t.Skip("Skipping test - grype not available")
	}

	assert.NotEmpty(t, version)
	t.Logf("Grype version: %s", version)
}

func TestGrypeScanner_ValidateInstallation(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)
	ctx := context.Background()

	err := scanner.ValidateInstallation(ctx)
	if err != nil {
		t.Logf("Grype installation validation failed: %v", err)
		t.Skip("Skipping test - grype not properly installed")
	}

	t.Log("Grype installation validated successfully")
}

func TestGrypeScanner_ScanVulnerabilities_InvalidPath(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 5)
	ctx := context.Background()
	options := DefaultVulnScanOptions()

	_, err := scanner.ScanVulnerabilities(ctx, "/nonexistent/path", options)
	assert.Error(t, err)
}

func TestGrypeScanner_ScanVulnerabilities_NilOptions(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)
	ctx := context.Background()

	// Test with current directory (should work if grype is installed)
	vulns, err := scanner.ScanVulnerabilities(ctx, ".", nil)
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		t.Logf("Grype not installed: %v", err)
		t.Skip("Skipping test - grype not available")
	}

	if err == nil {
		t.Logf("Found %d vulnerabilities", len(vulns))
		// Vulnerabilities might be 0 if scanning current directory has no issues
		// This is a successful case even with empty results
	} else {
		t.Logf("ScanVulnerabilities failed (expected if no vulnerable packages): %v", err)
	}
}

func TestGrypeScanner_FilterVulnerabilities(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)

	vulnerabilities := []*models.Vulnerability{
		{VulnID: "CVE-2023-0001", Severity: "Critical"},
		{VulnID: "CVE-2023-0002", Severity: "High"},
		{VulnID: "CVE-2023-0003", Severity: "Medium"},
		{VulnID: "CVE-2023-0004", Severity: "Low"},
		{VulnID: "CVE-2023-0005", Severity: "Critical", Fixes: []models.VulnerabilityFix{{Version: "1.2.3", State: "fixed"}}},
	}

	// Test severity filtering
	filtered := scanner.FilterVulnerabilities(vulnerabilities, models.SeverityHigh, false)
	assert.Len(t, filtered, 3) // Critical, High, Critical with fix

	// Test only fixed filtering
	fixedOnly := scanner.FilterVulnerabilities(vulnerabilities, models.SeverityUnknown, true)
	assert.Len(t, fixedOnly, 1) // Only the one with fixes

	// Test combined filtering
	highAndFixed := scanner.FilterVulnerabilities(vulnerabilities, models.SeverityHigh, true)
	assert.Len(t, highAndFixed, 1) // Only the critical with fix
}

func TestGrypeScanner_GroupVulnerabilitiesBySeverity(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)

	vulnerabilities := []*models.Vulnerability{
		{VulnID: "CVE-2023-0001", Severity: "Critical"},
		{VulnID: "CVE-2023-0002", Severity: "High"},
		{VulnID: "CVE-2023-0003", Severity: "High"},
		{VulnID: "CVE-2023-0004", Severity: "Medium"},
		{VulnID: "CVE-2023-0005", Severity: "Low"},
	}

	grouped := scanner.GroupVulnerabilitiesBySeverity(vulnerabilities)

	assert.Len(t, grouped["Critical"], 1)
	assert.Len(t, grouped["High"], 2)
	assert.Len(t, grouped["Medium"], 1)
	assert.Len(t, grouped["Low"], 1)
	assert.Equal(t, "CVE-2023-0001", grouped["Critical"][0].VulnID)
	assert.Equal(t, "CVE-2023-0002", grouped["High"][0].VulnID)
}

func TestGrypeScanner_CountVulnerabilitiesBySeverity(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)

	vulnerabilities := []*models.Vulnerability{
		{VulnID: "CVE-2023-0001", Severity: "Critical"},
		{VulnID: "CVE-2023-0002", Severity: "Critical"},
		{VulnID: "CVE-2023-0003", Severity: "High"},
		{VulnID: "CVE-2023-0004", Severity: "Medium"},
		{VulnID: "CVE-2023-0005", Severity: "Medium"},
		{VulnID: "CVE-2023-0006", Severity: "Medium"},
		{VulnID: "CVE-2023-0007", Severity: "Low"},
	}

	counts := scanner.CountVulnerabilitiesBySeverity(vulnerabilities)

	assert.Equal(t, 2, counts["Critical"])
	assert.Equal(t, 1, counts["High"])
	assert.Equal(t, 3, counts["Medium"])
	assert.Equal(t, 1, counts["Low"])
	assert.Equal(t, 0, counts["Unknown"]) // Should be 0 for missing severity
}

func TestGrypeScanner_ScanDirectory(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)
	ctx := context.Background()
	options := DefaultVulnScanOptions()

	// Test scanning current directory
	vulns, err := scanner.ScanDirectory(ctx, ".", options)
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		t.Logf("Grype not installed: %v", err)
		t.Skip("Skipping test - grype not available")
	}

	if err == nil {
		t.Logf("Directory scan found %d vulnerabilities", len(vulns))
		// Success case - directory scanned successfully
	} else {
		t.Logf("ScanDirectory failed (may be expected): %v", err)
	}
}

func TestGrypeScanner_ScanImage(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)
	ctx := context.Background()
	options := DefaultVulnScanOptions()

	// Test with a non-existent image (should fail)
	vulns, err := scanner.ScanImage(ctx, "nonexistent:latest", options)
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		t.Logf("Grype not installed: %v", err)
		t.Skip("Skipping test - grype not available")
	}

	// Should error because image doesn't exist
	assert.Error(t, err)
	assert.Nil(t, vulns)
}

func TestGrypeScanner_UpdateDatabase(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 60)
	ctx := context.Background()

	err := scanner.UpdateDatabase(ctx)
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		t.Logf("Grype not installed: %v", err)
		t.Skip("Skipping test - grype not available")
	}

	if err == nil {
		t.Log("Database update completed successfully")
	} else {
		t.Logf("Database update failed (may be expected in CI): %v", err)
	}
}

func TestGrypeScanner_GetDatabaseInfo(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)
	ctx := context.Background()

	info, err := scanner.GetDatabaseInfo(ctx)
	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		t.Logf("Grype not installed: %v", err)
		t.Skip("Skipping test - grype not available")
	}

	if err == nil {
		assert.NotNil(t, info)
		t.Logf("Database info retrieved: %+v", info)
	} else {
		t.Logf("GetDatabaseInfo failed (may be expected): %v", err)
	}
}

func TestGrypeScanner_ContextCancellation(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 30)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	options := DefaultVulnScanOptions()
	_, err := scanner.ScanVulnerabilities(ctx, ".", options)

	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		t.Skip("Skipping test - grype not available")
	}

	assert.Error(t, err)
	// Context cancellation might cause JSON parsing error or other errors
	assert.True(t, strings.Contains(err.Error(), "context") ||
		strings.Contains(err.Error(), "JSON") ||
		strings.Contains(err.Error(), "killed"))
}

func TestGrypeScanner_Timeout(t *testing.T) {
	scanner := NewGrypeScanner("grype", "/tmp", "/tmp/cache", 1) // 1 second timeout
	ctx := context.Background()
	options := DefaultVulnScanOptions()

	// Try to scan a large directory that would take longer than 1 second
	_, err := scanner.ScanVulnerabilities(ctx, "/usr", options)

	if err != nil && strings.Contains(err.Error(), "executable file not found") {
		t.Skip("Skipping test - grype not available")
	}

	if err != nil {
		t.Logf("ScanVulnerabilities failed (expected for timeout test): %v", err)
		// Should contain timeout, context deadline, or killed error
		assert.True(t, strings.Contains(err.Error(), "context deadline") ||
			strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "killed"))
	}
}
