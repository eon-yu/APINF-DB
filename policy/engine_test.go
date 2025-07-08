package policy

import (
	"testing"

	"oss-compliance-scanner/models"

	"github.com/stretchr/testify/assert"
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

// Tests for rules.go

func TestNewRuleEngine(t *testing.T) {
	engine := NewRuleEngine()
	assert.NotNil(t, engine)
	assert.Empty(t, engine.ruleSets)
	assert.NotNil(t, engine.globals)
}

func TestRuleEngine_LoadRulesFromString(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Test Rules"
description: "Test rule set"
rules:
  - id: "test-rule-1"
    name: "Test GPL License Block"
    description: "Block GPL licenses"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "GPL"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)
	assert.Len(t, engine.ruleSets, 1)
	assert.Equal(t, "Test Rules", engine.ruleSets[0].Name)
	assert.Len(t, engine.ruleSets[0].Rules, 1)
	assert.Equal(t, "test-rule-1", engine.ruleSets[0].Rules[0].ID)
}

func TestRuleEngine_LoadRulesFromString_InvalidYAML(t *testing.T) {
	engine := NewRuleEngine()

	invalidYAML := `
invalid yaml content
  missing: proper structure
`

	err := engine.LoadRulesFromString(invalidYAML)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse rules")
}

func TestRuleEngine_EvaluateComponent(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Component Rules"
rules:
  - id: "block-test-component"
    name: "Block Test Component"
    description: "Block components named test"
    type: "component"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "component_name"
        operator: "contains"
        value: "test"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	component := &models.Component{
		ID:      1,
		Name:    "test-package",
		Version: "1.0.0",
	}

	violations, err := engine.EvaluateComponent(component)
	assert.NoError(t, err)
	assert.Len(t, violations, 1)
	assert.Equal(t, "high", violations[0].Severity)
	assert.Contains(t, violations[0].Description, "Block Test Component")
}

func TestRuleEngine_EvaluateLicense(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "License Rules"
rules:
  - id: "block-gpl"
    name: "Block GPL License"
    description: "GPL licenses are not allowed"
    type: "license"
    enabled: true
    severity: "critical"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "GPL"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	component := &models.Component{
		ID:      1,
		Name:    "test-package",
		Version: "1.0.0",
	}

	violations, err := engine.EvaluateLicense("GPL", component)
	assert.NoError(t, err)
	assert.Len(t, violations, 1)
	assert.Equal(t, "critical", violations[0].Severity)
	assert.Contains(t, violations[0].Description, "GPL licenses are not allowed")
}

func TestRuleEngine_EvaluateVulnerability(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Vulnerability Rules"
rules:
  - id: "block-critical-vulns"
    name: "Block Critical Vulnerabilities"
    description: "Critical vulnerabilities are not allowed"
    type: "vulnerability"
    enabled: true
    severity: "critical"
    action: "block"
    conditions:
      - field: "severity"
        operator: "equals"
        value: "Critical"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	component := &models.Component{
		ID:      1,
		Name:    "test-package",
		Version: "1.0.0",
	}

	vulnerability := &models.Vulnerability{
		ID:          1,
		ComponentID: 1,
		VulnID:      "CVE-2023-1234",
		Severity:    "Critical",
		CVSS3Score:  9.8,
	}

	violations, err := engine.EvaluateVulnerability(vulnerability, component)
	assert.NoError(t, err)
	assert.Len(t, violations, 1)
	assert.Equal(t, "critical", violations[0].Severity)
	assert.NotNil(t, violations[0].VulnerabilityID)
}

func TestRuleEngine_OperatorEvaluation(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		component   *models.Component
		license     string
		expectMatch bool
	}{
		{
			name: "equals operator",
			yamlContent: `
version: "1.0"
name: "Test"
rules:
  - id: "test"
    name: "Test"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "MIT"
`,
			license:     "MIT",
			expectMatch: true,
		},
		{
			name: "contains operator",
			yamlContent: `
version: "1.0"
name: "Test"
rules:
  - id: "test"
    name: "Test"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "contains"
        value: "GPL"
`,
			license:     "GPL-3.0",
			expectMatch: true,
		},
		{
			name: "matches operator",
			yamlContent: `
version: "1.0"
name: "Test"
rules:
  - id: "test"
    name: "Test"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "matches"
        value: "GPL-.*"
`,
			license:     "GPL-3.0",
			expectMatch: true,
		},
		{
			name: "not_equals operator",
			yamlContent: `
version: "1.0"
name: "Test"
rules:
  - id: "test"
    name: "Test"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "not_equals"
        value: "MIT"
`,
			license:     "GPL",
			expectMatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := NewRuleEngine()
			err := engine.LoadRulesFromString(test.yamlContent)
			assert.NoError(t, err)

			component := &models.Component{
				ID:      1,
				Name:    "test-package",
				Version: "1.0.0",
			}

			violations, err := engine.EvaluateLicense(test.license, component)
			assert.NoError(t, err)

			if test.expectMatch {
				assert.Len(t, violations, 1)
			} else {
				assert.Empty(t, violations)
			}
		})
	}
}

func TestRuleEngine_NegateCondition(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Test"
rules:
  - id: "test"
    name: "Test"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "MIT"
        negate: true
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	component := &models.Component{
		ID:      1,
		Name:    "test-package",
		Version: "1.0.0",
	}

	// Should match GPL (not MIT)
	violations, err := engine.EvaluateLicense("GPL", component)
	assert.NoError(t, err)
	assert.Len(t, violations, 1)

	// Should not match MIT (because negate=true)
	violations, err = engine.EvaluateLicense("MIT", component)
	assert.NoError(t, err)
	assert.Empty(t, violations)
}

func TestRuleEngine_DisabledRule(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Test"
rules:
  - id: "test"
    name: "Test"
    type: "license"
    enabled: false
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "GPL"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	component := &models.Component{
		ID:      1,
		Name:    "test-package",
		Version: "1.0.0",
	}

	violations, err := engine.EvaluateLicense("GPL", component)
	assert.NoError(t, err)
	assert.Empty(t, violations) // Should be empty because rule is disabled
}

func TestRuleEngine_GetAllRules(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Test"
rules:
  - id: "rule1"
    name: "Rule 1"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "MIT"
  - id: "rule2"
    name: "Rule 2"
    type: "component"
    enabled: true
    severity: "medium"
    action: "warn"
    conditions:
      - field: "component_name"
        operator: "contains"
        value: "test"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	rules := engine.GetAllRules()
	assert.Len(t, rules, 2)
	assert.Equal(t, "rule1", rules[0].ID)
	assert.Equal(t, "rule2", rules[1].ID)
}

func TestRuleEngine_GetRuleByID(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Test"
rules:
  - id: "target-rule"
    name: "Target Rule"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "GPL"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	rule, err := engine.GetRuleByID("target-rule")
	assert.NoError(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, "target-rule", rule.ID)
	assert.Equal(t, "Target Rule", rule.Name)

	// Test non-existent rule
	rule, err = engine.GetRuleByID("non-existent")
	assert.Error(t, err)
	assert.Nil(t, rule)
}

func TestRuleEngine_ValidationErrors(t *testing.T) {
	engine := NewRuleEngine()

	// Test missing required fields
	invalidYaml := `
version: "1.0"
name: "Test"
rules:
  - id: ""
    name: "Test Rule"
    type: "license"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "license"
        operator: "equals"
        value: "MIT"
`

	err := engine.LoadRulesFromString(invalidYaml)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rules")
}

func TestRuleEngine_NumericOperators(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Test"
rules:
  - id: "test-cvss"
    name: "Test CVSS"
    type: "vulnerability"
    enabled: true
    severity: "critical"
    action: "block"
    conditions:
      - field: "cvss_score"
        operator: "greater_than"
        value: "7.0"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	component := &models.Component{
		ID:      1,
		Name:    "test-package",
		Version: "1.0.0",
	}

	vulnerability := &models.Vulnerability{
		ID:          1,
		ComponentID: 1,
		VulnID:      "CVE-2023-1234",
		Severity:    "Critical",
		CVSS3Score:  9.8,
	}

	violations, err := engine.EvaluateVulnerability(vulnerability, component)
	assert.NoError(t, err)
	assert.Len(t, violations, 1)
}

func TestRuleEngine_MultipleConditions(t *testing.T) {
	engine := NewRuleEngine()

	yamlContent := `
version: "1.0"
name: "Test"
rules:
  - id: "multiple-conditions"
    name: "Multiple Conditions"
    type: "component"
    enabled: true
    severity: "high"
    action: "block"
    conditions:
      - field: "component_name"
        operator: "contains"
        value: "test"
      - field: "component_version"
        operator: "equals"
        value: "1.0.0"
`

	err := engine.LoadRulesFromString(yamlContent)
	assert.NoError(t, err)

	// Should match both conditions
	component1 := &models.Component{
		ID:      1,
		Name:    "test-package",
		Version: "1.0.0",
	}

	violations, err := engine.EvaluateComponent(component1)
	assert.NoError(t, err)
	assert.Len(t, violations, 1)

	// Should not match (wrong version)
	component2 := &models.Component{
		ID:      2,
		Name:    "test-package",
		Version: "2.0.0",
	}

	violations, err = engine.EvaluateComponent(component2)
	assert.NoError(t, err)
	assert.Empty(t, violations)
}
