package policy

import (
	"testing"

	"oss-compliance-scanner/models"
)

func TestNewPolicyEngine(t *testing.T) {
	licensePolicies := []*models.LicensePolicy{
		{
			ID:          1,
			LicenseName: "MIT",
			Action:      models.PolicyActionAllow,
			IsActive:    true,
		},
	}

	vulnPolicies := []*models.VulnerabilityPolicy{
		{
			ID:               1,
			MinSeverityLevel: "High",
			Action:           models.PolicyActionBlock,
			IsActive:         true,
		},
	}

	globalSettings := models.GlobalPolicySettings{
		EnableLicenseCheck:       true,
		EnableVulnerabilityCheck: true,
	}

	engine := NewPolicyEngine(licensePolicies, vulnPolicies, globalSettings)

	if engine == nil {
		t.Error("NewPolicyEngine should return a valid engine")
	}

	if len(engine.licensePolicies) != 1 {
		t.Errorf("Expected 1 license policy, got %d", len(engine.licensePolicies))
	}

	if len(engine.vulnerabilityPolicies) != 1 {
		t.Errorf("Expected 1 vulnerability policy, got %d", len(engine.vulnerabilityPolicies))
	}
}

func TestPolicyEngine_EvaluateCompliance(t *testing.T) {
	licensePolicies := []*models.LicensePolicy{
		{
			ID:          1,
			LicenseName: "GPL-3.0",
			Action:      models.PolicyActionBlock,
			Reason:      "Copyleft license not allowed",
			IsActive:    true,
		},
	}

	vulnPolicies := []*models.VulnerabilityPolicy{
		{
			ID:               1,
			MinSeverityLevel: "High",
			Action:           models.PolicyActionBlock,
			IsActive:         true,
		},
	}

	globalSettings := models.GlobalPolicySettings{
		EnableLicenseCheck:       true,
		EnableVulnerabilityCheck: true,
	}

	engine := NewPolicyEngine(licensePolicies, vulnPolicies, globalSettings)

	sbom := &models.SBOM{
		ID:         1,
		RepoName:   "test-repo",
		ModulePath: "backend",
	}

	components := []*models.Component{
		{
			ID:       1,
			Name:     "test-package",
			Version:  "1.0.0",
			Licenses: []string{"GPL-3.0"},
		},
	}

	vulnerabilities := []*models.Vulnerability{
		{
			ID:          1,
			ComponentID: 1,
			VulnID:      "CVE-2021-1234",
			Severity:    "Critical",
		},
	}

	result, err := engine.EvaluateCompliance(sbom, components, vulnerabilities)
	if err != nil {
		t.Errorf("EvaluateCompliance() error = %v", err)
	}

	if result == nil {
		t.Fatal("EvaluateCompliance() should return a result")
	}

	if result.SBOMID != 1 {
		t.Errorf("Expected SBOMID 1, got %d", result.SBOMID)
	}

	if result.TotalComponents != 1 {
		t.Errorf("Expected 1 component, got %d", result.TotalComponents)
	}

	if result.TotalVulnerabilities != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", result.TotalVulnerabilities)
	}

	// Should have license violations for GPL-3.0
	if len(result.LicenseViolations) == 0 {
		t.Error("Expected license violations for GPL-3.0")
	}

	// Should have vulnerability violations for Critical severity
	if len(result.VulnViolations) == 0 {
		t.Error("Expected vulnerability violations for Critical severity")
	}
}

func TestPolicyEngine_EvaluateCompliance_NoViolations(t *testing.T) {
	licensePolicies := []*models.LicensePolicy{
		{
			ID:          1,
			LicenseName: "MIT",
			Action:      models.PolicyActionAllow,
			IsActive:    true,
		},
	}

	vulnPolicies := []*models.VulnerabilityPolicy{
		{
			ID:               1,
			MinSeverityLevel: "Critical",
			Action:           models.PolicyActionBlock,
			IsActive:         true,
		},
	}

	globalSettings := models.GlobalPolicySettings{
		EnableLicenseCheck:       true,
		EnableVulnerabilityCheck: true,
	}

	engine := NewPolicyEngine(licensePolicies, vulnPolicies, globalSettings)

	sbom := &models.SBOM{
		ID:         1,
		RepoName:   "test-repo",
		ModulePath: "frontend",
	}

	components := []*models.Component{
		{
			ID:       1,
			Name:     "safe-package",
			Version:  "2.0.0",
			Licenses: []string{"MIT"},
		},
	}

	vulnerabilities := []*models.Vulnerability{
		{
			ID:          1,
			ComponentID: 1,
			VulnID:      "CVE-2021-1234",
			Severity:    "Medium",
		},
	}

	result, err := engine.EvaluateCompliance(sbom, components, vulnerabilities)
	if err != nil {
		t.Errorf("EvaluateCompliance() error = %v", err)
	}

	// Should have no license violations for MIT
	if len(result.LicenseViolations) > 0 {
		t.Error("Expected no license violations for MIT")
	}

	// Should have no vulnerability violations for Medium severity when policy requires Critical
	if len(result.VulnViolations) > 0 {
		t.Error("Expected no vulnerability violations for Medium severity")
	}
}

func TestPolicyEngine_DisabledChecks(t *testing.T) {
	engine := NewPolicyEngine(nil, nil, models.GlobalPolicySettings{
		EnableLicenseCheck:       false,
		EnableVulnerabilityCheck: false,
	})

	sbom := &models.SBOM{
		ID:       1,
		RepoName: "test-repo",
	}

	components := []*models.Component{
		{
			ID:       1,
			Name:     "test-package",
			Version:  "1.0.0",
			Licenses: []string{"GPL-3.0"},
		},
	}

	vulnerabilities := []*models.Vulnerability{
		{
			ID:       1,
			VulnID:   "CVE-2021-1234",
			Severity: "Critical",
		},
	}

	result, err := engine.EvaluateCompliance(sbom, components, vulnerabilities)
	if err != nil {
		t.Errorf("EvaluateCompliance() error = %v", err)
	}

	// Should have no violations when checks are disabled
	if len(result.LicenseViolations) > 0 {
		t.Error("Expected no license violations when license check is disabled")
	}

	if len(result.VulnViolations) > 0 {
		t.Error("Expected no vulnerability violations when vulnerability check is disabled")
	}
}

func TestPolicyEngine_UnknownLicense(t *testing.T) {
	engine := NewPolicyEngine(nil, nil, models.GlobalPolicySettings{
		EnableLicenseCheck: true,
	})

	sbom := &models.SBOM{
		ID:       1,
		RepoName: "test-repo",
	}

	components := []*models.Component{
		{
			ID:       1,
			Name:     "unknown-package",
			Version:  "1.0.0",
			Licenses: []string{}, // No license information
		},
	}

	result, err := engine.EvaluateCompliance(sbom, components, nil)
	if err != nil {
		t.Errorf("EvaluateCompliance() error = %v", err)
	}

	// Should handle unknown licenses appropriately
	if result == nil {
		t.Fatal("EvaluateCompliance() should return a result")
	}

	// The behavior for unknown licenses depends on implementation
	// This test ensures it doesn't crash
}

func TestViolationSummary_Calculation(t *testing.T) {
	violations := []*models.PolicyViolation{
		{Severity: "Critical", ViolationType: models.ViolationTypeLicense},
		{Severity: "High", ViolationType: models.ViolationTypeVulnerability},
		{Severity: "Medium", ViolationType: models.ViolationTypeLicense},
		{Severity: "Low", ViolationType: models.ViolationTypeVulnerability},
	}

	engine := NewPolicyEngine(nil, nil, models.GlobalPolicySettings{})
	summary := engine.calculateSummary(violations[:2], violations[2:], []*models.PolicyViolation{})

	if summary.TotalViolations != 4 {
		t.Errorf("Expected 4 total violations, got %d", summary.TotalViolations)
	}

	if summary.CriticalViolations != 1 {
		t.Errorf("Expected 1 critical violation, got %d", summary.CriticalViolations)
	}

	if summary.LicenseViolations != 2 {
		t.Errorf("Expected 2 license violations, got %d", summary.LicenseViolations)
	}

	if summary.VulnViolations != 2 {
		t.Errorf("Expected 2 vulnerability violations, got %d", summary.VulnViolations)
	}
}
