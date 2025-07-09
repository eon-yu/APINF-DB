package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
		Metadata: map[string]any{
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

	assert.NotNil(t, output.Source)
}

// Tests for vulnerability.go

func TestVulnerability_MarshalVulnerabilityFields(t *testing.T) {
	vuln := &Vulnerability{
		URLs: []string{"https://example.com/cve-1", "https://example.com/cve-2"},
		Fixes: []VulnerabilityFix{
			{Version: "1.2.3", State: "fixed"},
			{Version: "1.2.4", State: "fixed"},
		},
		Metadata: map[string]any{
			"source":     "grype",
			"confidence": 0.95,
		},
	}

	err := vuln.MarshalVulnerabilityFields()
	assert.NoError(t, err)
	assert.NotEmpty(t, vuln.URLsJSON)
	assert.NotEmpty(t, vuln.FixesJSON)
	assert.NotEmpty(t, vuln.MetadataJSON)
	assert.Contains(t, vuln.URLsJSON, "https://example.com/cve-1")
}

func TestVulnerability_UnmarshalVulnerabilityFields(t *testing.T) {
	vuln := &Vulnerability{
		URLsJSON:     `["https://example.com/cve-1","https://example.com/cve-2"]`,
		FixesJSON:    `[{"version":"1.2.3","state":"fixed"}]`,
		MetadataJSON: `{"source":"grype","confidence":0.95}`,
	}

	err := vuln.UnmarshalVulnerabilityFields()
	assert.NoError(t, err)
	assert.Len(t, vuln.URLs, 2)
	assert.Equal(t, "https://example.com/cve-1", vuln.URLs[0])
	assert.Len(t, vuln.Fixes, 1)
	assert.Equal(t, "1.2.3", vuln.Fixes[0].Version)
	assert.Equal(t, "fixed", vuln.Fixes[0].State)
	assert.Equal(t, "grype", vuln.Metadata["source"])
}

func TestVulnerability_UnmarshalVulnerabilityFields_InvalidJSON(t *testing.T) {
	vuln := &Vulnerability{
		URLsJSON: `invalid json`,
	}

	err := vuln.UnmarshalVulnerabilityFields()
	assert.Error(t, err)
}

func TestSeverityLevel_ParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected SeverityLevel
	}{
		{"Critical", SeverityCritical},
		{"High", SeverityHigh},
		{"Medium", SeverityMedium},
		{"Low", SeverityLow},
		{"Negligible", SeverityNegligible},
		{"Unknown", SeverityUnknown},
		{"invalid", SeverityUnknown},
		{"", SeverityUnknown},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := ParseSeverity(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestSeverityLevel_String(t *testing.T) {
	tests := []struct {
		level    SeverityLevel
		expected string
	}{
		{SeverityCritical, "Critical"},
		{SeverityHigh, "High"},
		{SeverityMedium, "Medium"},
		{SeverityLow, "Low"},
		{SeverityNegligible, "Negligible"},
		{SeverityUnknown, "Unknown"},
		{SeverityLevel(999), "Unknown"}, // Invalid level
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := test.level.String()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGrypeOutput_Structure(t *testing.T) {
	output := &GrypeOutput{
		Matches: []GrypeMatch{
			{
				Vulnerability: GrypeVulnerability{
					ID:         "CVE-2023-1234",
					Severity:   "High",
					DataSource: "nvd",
				},
				Artifact: GrypeArtifact{
					Name:    "test-package",
					Version: "1.0.0",
				},
			},
		},
		Source: GrypeSource{
			Type:   "directory",
			Target: "/path/to/source",
		},
		Distro: GrypeDistro{
			Name:    "ubuntu",
			Version: "20.04",
		},
	}

	assert.Len(t, output.Matches, 1)
	assert.Equal(t, "CVE-2023-1234", output.Matches[0].Vulnerability.ID)
	assert.Equal(t, "High", output.Matches[0].Vulnerability.Severity)
	assert.Equal(t, "test-package", output.Matches[0].Artifact.Name)
	assert.Equal(t, "directory", output.Source.Type)
	assert.Equal(t, "ubuntu", output.Distro.Name)
}

// Tests for policy.go

func TestPolicyViolation_MarshalPolicyViolationFields(t *testing.T) {
	violation := &PolicyViolation{
		Metadata: map[string]any{
			"rule":       "license-check",
			"confidence": 0.98,
			"details":    "GPL license not allowed",
		},
	}

	err := violation.MarshalPolicyViolationFields()
	assert.NoError(t, err)
	assert.NotEmpty(t, violation.MetadataJSON)
	assert.Contains(t, violation.MetadataJSON, "license-check")
}

func TestPolicyViolation_UnmarshalPolicyViolationFields(t *testing.T) {
	violation := &PolicyViolation{
		MetadataJSON: `{"rule":"license-check","confidence":0.98,"details":"GPL license not allowed"}`,
	}

	err := violation.UnmarshalPolicyViolationFields()
	assert.NoError(t, err)
	assert.Equal(t, "license-check", violation.Metadata["rule"])
	assert.Equal(t, 0.98, violation.Metadata["confidence"])
	assert.Equal(t, "GPL license not allowed", violation.Metadata["details"])
}

func TestPolicyViolation_UnmarshalPolicyViolationFields_InvalidJSON(t *testing.T) {
	violation := &PolicyViolation{
		MetadataJSON: `invalid json`,
	}

	err := violation.UnmarshalPolicyViolationFields()
	assert.Error(t, err)
}

func TestScanResult_MarshalScanResultFields(t *testing.T) {
	result := &ScanResult{
		Metadata: map[string]any{
			"scanner_version": "1.0.0",
			"scan_options":    []string{"--all", "--verbose"},
			"duration":        "5m30s",
		},
	}

	err := result.MarshalScanResultFields()
	assert.NoError(t, err)
	assert.NotEmpty(t, result.MetadataJSON)
	assert.Contains(t, result.MetadataJSON, "scanner_version")
}

func TestScanResult_UnmarshalScanResultFields(t *testing.T) {
	result := &ScanResult{
		MetadataJSON: `{"scanner_version":"1.0.0","duration":"5m30s"}`,
	}

	err := result.UnmarshalScanResultFields()
	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", result.Metadata["scanner_version"])
	assert.Equal(t, "5m30s", result.Metadata["duration"])
}

func TestScanResult_CalculateOverallRisk(t *testing.T) {
	tests := []struct {
		name          string
		criticalVulns int
		highVulns     int
		mediumVulns   int
		lowVulns      int
		expected      RiskLevel
	}{
		{"Critical risk", 5, 10, 20, 30, RiskLevelCritical},
		{"High risk", 0, 8, 15, 25, RiskLevelHigh},
		{"Medium risk", 0, 0, 12, 20, RiskLevelMedium},
		{"Low risk", 0, 0, 0, 5, RiskLevelLow},
		{"No vulnerabilities", 0, 0, 0, 0, RiskLevelLow},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := &ScanResult{
				CriticalVulns: test.criticalVulns,
				HighVulns:     test.highVulns,
				MediumVulns:   test.mediumVulns,
				LowVulns:      test.lowVulns,
			}

			risk := result.CalculateOverallRisk()
			assert.Equal(t, test.expected, risk)
		})
	}
}

func TestPolicyAction_Constants(t *testing.T) {
	assert.Equal(t, PolicyAction("allow"), PolicyActionAllow)
	assert.Equal(t, PolicyAction("warn"), PolicyActionWarn)
	assert.Equal(t, PolicyAction("block"), PolicyActionBlock)
	assert.Equal(t, PolicyAction("fail"), PolicyActionFail)
}

func TestViolationType_Constants(t *testing.T) {
	assert.Equal(t, ViolationType("license"), ViolationTypeLicense)
	assert.Equal(t, ViolationType("vulnerability"), ViolationTypeVulnerability)
}

func TestViolationStatus_Constants(t *testing.T) {
	assert.Equal(t, ViolationStatus("open"), ViolationStatusOpen)
	assert.Equal(t, ViolationStatus("ignored"), ViolationStatusIgnored)
	assert.Equal(t, ViolationStatus("resolved"), ViolationStatusResolved)
	assert.Equal(t, ViolationStatus("false_positive"), ViolationStatusFalsePositive)
}

func TestScanStatus_Constants(t *testing.T) {
	assert.Equal(t, ScanStatus("pending"), ScanStatusPending)
	assert.Equal(t, ScanStatus("running"), ScanStatusRunning)
	assert.Equal(t, ScanStatus("completed"), ScanStatusCompleted)
	assert.Equal(t, ScanStatus("failed"), ScanStatusFailed)
	assert.Equal(t, ScanStatus("cancelled"), ScanStatusCancelled)
}

func TestRiskLevel_Constants(t *testing.T) {
	assert.Equal(t, RiskLevel("low"), RiskLevelLow)
	assert.Equal(t, RiskLevel("medium"), RiskLevelMedium)
	assert.Equal(t, RiskLevel("high"), RiskLevelHigh)
	assert.Equal(t, RiskLevel("critical"), RiskLevelCritical)
}

func TestPolicyConfig_Structure(t *testing.T) {
	config := &PolicyConfig{
		LicensePolicies: []LicensePolicy{
			{LicenseName: "MIT", Action: PolicyActionAllow},
			{LicenseName: "GPL", Action: PolicyActionBlock},
		},
		VulnerabilityPolicies: []VulnerabilityPolicy{
			{MinSeverityLevel: "High", Action: PolicyActionFail},
		},
		GlobalSettings: GlobalPolicySettings{
			EnableLicenseCheck:       true,
			EnableVulnerabilityCheck: true,
			ScanTimeout:              30,
		},
	}

	assert.Len(t, config.LicensePolicies, 2)
	assert.Equal(t, "MIT", config.LicensePolicies[0].LicenseName)
	assert.Equal(t, PolicyActionAllow, config.LicensePolicies[0].Action)
	assert.Len(t, config.VulnerabilityPolicies, 1)
	assert.Equal(t, "High", config.VulnerabilityPolicies[0].MinSeverityLevel)
	assert.True(t, config.GlobalSettings.EnableLicenseCheck)
}

func TestNotificationSettings_Structure(t *testing.T) {
	settings := &NotificationSettings{
		SlackWebhookURL:      "https://hooks.slack.com/test",
		SlackChannel:         "#security",
		NotifyOnViolation:    true,
		NotifyOnResolution:   false,
		MinSeverityLevel:     "High",
		NotificationBatching: true,
		BatchingInterval:     15,
	}

	assert.Equal(t, "https://hooks.slack.com/test", settings.SlackWebhookURL)
	assert.Equal(t, "#security", settings.SlackChannel)
	assert.True(t, settings.NotifyOnViolation)
	assert.False(t, settings.NotifyOnResolution)
	assert.Equal(t, "High", settings.MinSeverityLevel)
	assert.True(t, settings.NotificationBatching)
	assert.Equal(t, 15, settings.BatchingInterval)
}
