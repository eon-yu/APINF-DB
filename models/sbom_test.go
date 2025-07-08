package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSBOM_Fields(t *testing.T) {
	sbom := &SBOM{
		ID:             1,
		RepoName:       "test-repo",
		ModulePath:     "backend",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		ComponentCount: 15,
	}

	if sbom.ID != 1 {
		t.Errorf("Expected ID 1, got %d", sbom.ID)
	}

	if sbom.RepoName != "test-repo" {
		t.Errorf("Expected RepoName 'test-repo', got %s", sbom.RepoName)
	}

	if sbom.ComponentCount != 15 {
		t.Errorf("Expected ComponentCount 15, got %d", sbom.ComponentCount)
	}
}

func TestComponent_MarshalComponentFields(t *testing.T) {
	component := &Component{
		Name:     "express",
		Version:  "4.17.1",
		Type:     "library",
		Language: "javascript",
		Licenses: []string{"MIT", "Apache-2.0"},
		Locations: []ComponentLocation{
			{Path: "/app/package.json"},
			{Path: "/app/node_modules/express"},
		},
		Metadata: map[string]interface{}{
			"description": "Fast, unopinionated, minimalist web framework",
			"author":      "TJ Holowaychuk",
		},
	}

	err := component.MarshalComponentFields()
	if err != nil {
		t.Errorf("MarshalComponentFields() error = %v", err)
	}

	// Check if JSON fields were populated
	if component.LicensesJSON == "" {
		t.Error("LicensesJSON should be populated")
	}

	if component.LocationsJSON == "" {
		t.Error("LocationsJSON should be populated")
	}

	if component.MetadataJSON == "" {
		t.Error("MetadataJSON should be populated")
	}

	// Verify JSON content
	var licenses []string
	err = json.Unmarshal([]byte(component.LicensesJSON), &licenses)
	if err != nil {
		t.Errorf("Failed to unmarshal licenses: %v", err)
	}

	if len(licenses) != 2 || licenses[0] != "MIT" || licenses[1] != "Apache-2.0" {
		t.Errorf("Unexpected licenses: %v", licenses)
	}
}

func TestComponent_UnmarshalComponentFields(t *testing.T) {
	component := &Component{
		LicensesJSON:  `["MIT", "Apache-2.0"]`,
		LocationsJSON: `[{"path": "/app/package.json"}, {"path": "/app/node_modules/express"}]`,
		MetadataJSON:  `{"description": "Test package", "author": "Test Author"}`,
	}

	err := component.UnmarshalComponentFields()
	if err != nil {
		t.Errorf("UnmarshalComponentFields() error = %v", err)
	}

	// Check licenses
	if len(component.Licenses) != 2 {
		t.Errorf("Expected 2 licenses, got %d", len(component.Licenses))
	}

	if component.Licenses[0] != "MIT" || component.Licenses[1] != "Apache-2.0" {
		t.Errorf("Unexpected licenses: %v", component.Licenses)
	}

	// Check locations
	if len(component.Locations) != 2 {
		t.Errorf("Expected 2 locations, got %d", len(component.Locations))
	}

	if component.Locations[0].Path != "/app/package.json" {
		t.Errorf("Unexpected first location path: %s", component.Locations[0].Path)
	}

	// Check metadata
	if len(component.Metadata) != 2 {
		t.Errorf("Expected 2 metadata entries, got %d", len(component.Metadata))
	}

	if component.Metadata["description"] != "Test package" {
		t.Errorf("Unexpected description: %v", component.Metadata["description"])
	}
}

func TestSyftArtifact_UnmarshalLicenses(t *testing.T) {
	tests := []struct {
		name        string
		licensesRaw json.RawMessage
		expected    []string
	}{
		{
			name:        "string array",
			licensesRaw: json.RawMessage(`["MIT", "Apache-2.0"]`),
			expected:    []string{"MIT", "Apache-2.0"},
		},
		{
			name:        "object array",
			licensesRaw: json.RawMessage(`[{"name": "MIT"}, {"id": "Apache-2.0"}]`),
			expected:    []string{"MIT", "Apache-2.0"},
		},
		{
			name:        "single string",
			licensesRaw: json.RawMessage(`"MIT"`),
			expected:    []string{"MIT"},
		},
		{
			name:        "empty array",
			licensesRaw: json.RawMessage(`[]`),
			expected:    []string{},
		},
		{
			name:        "null values filtered",
			licensesRaw: json.RawMessage(`["MIT", "NOASSERTION", "Apache-2.0", "UNKNOWN"]`),
			expected:    []string{"MIT", "Apache-2.0"},
		},
		{
			name:        "empty raw message",
			licensesRaw: json.RawMessage(``),
			expected:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact := &SyftArtifact{
				LicensesRaw: tt.licensesRaw,
			}

			result := artifact.UnmarshalLicenses()

			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d licenses, got %d", len(tt.expected), len(result))
				return
			}

			for i, license := range result {
				if license != tt.expected[i] {
					t.Errorf("Expected license[%d] = %s, got %s", i, tt.expected[i], license)
				}
			}
		})
	}
}

func TestComponentLocation_Fields(t *testing.T) {
	location := ComponentLocation{
		Path:      "/app/package.json",
		LayerID:   "sha256:abc123",
		Namespace: "app",
	}

	if location.Path != "/app/package.json" {
		t.Errorf("Expected Path '/app/package.json', got %s", location.Path)
	}

	if location.LayerID != "sha256:abc123" {
		t.Errorf("Expected LayerID 'sha256:abc123', got %s", location.LayerID)
	}

	if location.Namespace != "app" {
		t.Errorf("Expected Namespace 'app', got %s", location.Namespace)
	}
}

func TestSyftOutput_Structure(t *testing.T) {
	output := &SyftOutput{
		Schema: SyftSchema{
			Version: "1.0",
			URL:     "https://example.com/schema",
		},
		Distro: SyftDistro{
			Name:    "ubuntu",
			Version: "20.04",
			IDLike:  "debian",
		},
		Source: SyftSource{
			Type:   "directory",
			Target: "/app",
		},
		Artifacts: []SyftArtifact{
			{
				ID:       "package-1",
				Name:     "express",
				Version:  "4.17.1",
				Type:     "npm",
				Language: "javascript",
			},
		},
	}

	if output.Schema.Version != "1.0" {
		t.Errorf("Expected Schema Version '1.0', got %s", output.Schema.Version)
	}

	if output.Distro.Name != "ubuntu" {
		t.Errorf("Expected Distro Name 'ubuntu', got %s", output.Distro.Name)
	}

	if len(output.Artifacts) != 1 {
		t.Errorf("Expected 1 artifact, got %d", len(output.Artifacts))
	}

	if output.Artifacts[0].Name != "express" {
		t.Errorf("Expected Artifact Name 'express', got %s", output.Artifacts[0].Name)
	}
}
