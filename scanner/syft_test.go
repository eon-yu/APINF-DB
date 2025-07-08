package scanner

import (
	"context"
	"testing"
	"time"

	"oss-compliance-scanner/models"
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
