package policy

import (
	"fmt"
	"strings"
	"time"

	"oss-compliance-scanner/models"
)

// PolicyEngine handles policy evaluation for OSS compliance
type PolicyEngine struct {
	licensePolicies       []*models.LicensePolicy
	vulnerabilityPolicies []*models.VulnerabilityPolicy
	globalSettings        models.GlobalPolicySettings
	ruleEngine            *RuleEngine
}

// NewPolicyEngine creates a new policy engine instance
func NewPolicyEngine(licensePolicies []*models.LicensePolicy, vulnPolicies []*models.VulnerabilityPolicy, settings models.GlobalPolicySettings) *PolicyEngine {
	return &PolicyEngine{
		licensePolicies:       licensePolicies,
		vulnerabilityPolicies: vulnPolicies,
		globalSettings:        settings,
		ruleEngine:            NewRuleEngine(),
	}
}

// SetRuleEngine sets a custom rule engine
func (pe *PolicyEngine) SetRuleEngine(ruleEngine *RuleEngine) {
	pe.ruleEngine = ruleEngine
}

// LoadCustomRules loads custom rules from a file
func (pe *PolicyEngine) LoadCustomRules(filePath string) error {
	return pe.ruleEngine.LoadRulesFromFile(filePath)
}

// EvaluationResult represents the result of policy evaluation
type EvaluationResult struct {
	SBOMID               int                       `json:"sbom_id"`
	RepoName             string                    `json:"repo_name"`
	ModulePath           string                    `json:"module_path"`
	TotalComponents      int                       `json:"total_components"`
	TotalVulnerabilities int                       `json:"total_vulnerabilities"`
	LicenseViolations    []*models.PolicyViolation `json:"license_violations"`
	VulnViolations       []*models.PolicyViolation `json:"vulnerability_violations"`
	CustomRuleViolations []*models.PolicyViolation `json:"custom_rule_violations"`
	Summary              ViolationSummary          `json:"summary"`
	OverallStatus        models.PolicyAction       `json:"overall_status"`
	Recommendations      []string                  `json:"recommendations"`
}

// ViolationSummary provides a summary of violations
type ViolationSummary struct {
	TotalViolations    int `json:"total_violations"`
	CriticalViolations int `json:"critical_violations"`
	HighViolations     int `json:"high_violations"`
	MediumViolations   int `json:"medium_violations"`
	LowViolations      int `json:"low_violations"`
	LicenseViolations  int `json:"license_violations"`
	VulnViolations     int `json:"vulnerability_violations"`
	BlockingViolations int `json:"blocking_violations"`
	WarningViolations  int `json:"warning_violations"`
}

// EvaluateCompliance evaluates compliance for an SBOM and its components/vulnerabilities
func (pe *PolicyEngine) EvaluateCompliance(sbom *models.SBOM, components []*models.Component, vulnerabilities []*models.Vulnerability) (*EvaluationResult, error) {
	result := &EvaluationResult{
		SBOMID:               sbom.ID,
		RepoName:             sbom.RepoName,
		ModulePath:           sbom.ModulePath,
		TotalComponents:      len(components),
		TotalVulnerabilities: len(vulnerabilities),
		LicenseViolations:    []*models.PolicyViolation{},
		VulnViolations:       []*models.PolicyViolation{},
		CustomRuleViolations: []*models.PolicyViolation{},
		Recommendations:      []string{},
	}

	// Evaluate license policies
	if pe.globalSettings.EnableLicenseCheck {
		licenseViolations, err := pe.evaluateLicensePolicies(sbom, components)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate license policies: %w", err)
		}
		result.LicenseViolations = licenseViolations
	}

	// Evaluate vulnerability policies
	if pe.globalSettings.EnableVulnerabilityCheck {
		vulnViolations, err := pe.evaluateVulnerabilityPolicies(sbom, components, vulnerabilities)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate vulnerability policies: %w", err)
		}
		result.VulnViolations = vulnViolations
	}

	// Evaluate custom rules
	if pe.ruleEngine != nil {
		customViolations, err := pe.evaluateCustomRules(sbom, components, vulnerabilities)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate custom rules: %w", err)
		}
		result.CustomRuleViolations = customViolations
	}

	// Calculate summary
	result.Summary = pe.calculateSummary(result.LicenseViolations, result.VulnViolations, result.CustomRuleViolations)

	// Determine overall status
	result.OverallStatus = pe.determineOverallStatus(result.LicenseViolations, result.VulnViolations, result.CustomRuleViolations)

	// Generate recommendations
	result.Recommendations = pe.generateRecommendations(result)

	return result, nil
}

// evaluateLicensePolicies evaluates license compliance policies
func (pe *PolicyEngine) evaluateLicensePolicies(sbom *models.SBOM, components []*models.Component) ([]*models.PolicyViolation, error) {
	var violations []*models.PolicyViolation

	for _, component := range components {
		if len(component.Licenses) == 0 {
			// Handle components with unknown licenses
			violation := pe.createLicenseViolation(sbom, component, "Unknown", "No license information available")
			if violation != nil {
				violations = append(violations, violation)
			}
			continue
		}

		for _, license := range component.Licenses {
			violation := pe.checkLicensePolicy(sbom, component, license)
			if violation != nil {
				violations = append(violations, violation)
			}
		}
	}

	return violations, nil
}

// evaluateVulnerabilityPolicies evaluates vulnerability policies
func (pe *PolicyEngine) evaluateVulnerabilityPolicies(sbom *models.SBOM, components []*models.Component, vulnerabilities []*models.Vulnerability) ([]*models.PolicyViolation, error) {
	var violations []*models.PolicyViolation

	// Group vulnerabilities by component
	vulnByComponent := make(map[int][]*models.Vulnerability)
	for _, vuln := range vulnerabilities {
		vulnByComponent[vuln.ComponentID] = append(vulnByComponent[vuln.ComponentID], vuln)
	}

	// Evaluate each vulnerability
	for _, vuln := range vulnerabilities {
		violation := pe.checkVulnerabilityPolicy(sbom, vuln)
		if violation != nil {
			violations = append(violations, violation)
		}
	}

	return violations, nil
}

// checkLicensePolicy checks if a license violates any policy
func (pe *PolicyEngine) checkLicensePolicy(sbom *models.SBOM, component *models.Component, licenseName string) *models.PolicyViolation {
	// Normalize license name
	licenseName = normalizeLicenseName(licenseName)

	// Find matching policy
	var matchedPolicy *models.LicensePolicy
	for _, policy := range pe.licensePolicies {
		if policy.IsActive && matchesLicense(policy.LicenseName, licenseName) {
			matchedPolicy = policy
			break
		}
	}

	// If no specific policy found, check for default policies
	if matchedPolicy == nil {
		matchedPolicy = pe.getDefaultLicensePolicy(licenseName)
	}

	// Create violation if policy requires action
	if matchedPolicy != nil && (matchedPolicy.Action == models.PolicyActionBlock || matchedPolicy.Action == models.PolicyActionWarn || matchedPolicy.Action == models.PolicyActionFail) {
		return &models.PolicyViolation{
			SBOMID:            sbom.ID,
			ComponentID:       component.ID,
			ViolationType:     models.ViolationTypeLicense,
			Severity:          mapPolicyActionToSeverity(matchedPolicy.Action),
			PolicyID:          matchedPolicy.ID,
			Description:       fmt.Sprintf("License '%s' in component '%s@%s' violates policy", licenseName, component.Name, component.Version),
			RecommendedAction: fmt.Sprintf("Action required: %s. Reason: %s", matchedPolicy.Action, matchedPolicy.Reason),
			Status:            models.ViolationStatusOpen,
			Metadata: map[string]interface{}{
				"license_name":      licenseName,
				"component_name":    component.Name,
				"component_version": component.Version,
				"policy_reason":     matchedPolicy.Reason,
				"purl":              component.PURL,
			},
		}
	}

	return nil
}

// checkVulnerabilityPolicy checks if a vulnerability violates any policy
func (pe *PolicyEngine) checkVulnerabilityPolicy(sbom *models.SBOM, vuln *models.Vulnerability) *models.PolicyViolation {
	severity := models.ParseSeverity(vuln.Severity)

	for _, policy := range pe.vulnerabilityPolicies {
		if !policy.IsActive {
			continue
		}

		policyMinSeverity := models.ParseSeverity(policy.MinSeverityLevel)

		// Check if vulnerability meets policy criteria
		if severity >= policyMinSeverity && vuln.CVSS3Score <= policy.MaxCVSSScore {
			// Check grace period
			if policy.GracePeriodDays > 0 && vuln.PublishedDate != nil {
				graceEnd := vuln.PublishedDate.AddDate(0, 0, policy.GracePeriodDays)
				if time.Now().Before(graceEnd) {
					continue // Still within grace period
				}
			}

			// Check if fix is available and policy ignores unfixed
			if policy.IgnoreFixAvailable && len(vuln.Fixes) == 0 {
				continue
			}

			// Create violation if policy requires action
			if policy.Action == models.PolicyActionBlock || policy.Action == models.PolicyActionWarn || policy.Action == models.PolicyActionFail {
				return &models.PolicyViolation{
					SBOMID:            sbom.ID,
					ComponentID:       vuln.ComponentID,
					VulnerabilityID:   &vuln.ID,
					ViolationType:     models.ViolationTypeVulnerability,
					Severity:          vuln.Severity,
					PolicyID:          policy.ID,
					Description:       fmt.Sprintf("Vulnerability %s (%s) with CVSS score %.1f violates policy", vuln.VulnID, vuln.Severity, vuln.CVSS3Score),
					RecommendedAction: pe.generateVulnRecommendation(vuln, policy),
					Status:            models.ViolationStatusOpen,
					Metadata: map[string]interface{}{
						"vuln_id":         vuln.VulnID,
						"cvss3_score":     vuln.CVSS3Score,
						"cvss2_score":     vuln.CVSS2Score,
						"published_date":  vuln.PublishedDate,
						"fixes_available": len(vuln.Fixes) > 0,
						"grace_period":    policy.GracePeriodDays,
					},
				}
			}
		}
	}

	return nil
}

// createLicenseViolation creates a violation for unknown licenses
func (pe *PolicyEngine) createLicenseViolation(sbom *models.SBOM, component *models.Component, licenseName, description string) *models.PolicyViolation {
	// Find policy for unknown licenses
	for _, policy := range pe.licensePolicies {
		if policy.IsActive && (policy.LicenseName == "Unknown" || policy.LicenseName == "UNKNOWN" || policy.LicenseName == "*") {
			if policy.Action == models.PolicyActionBlock || policy.Action == models.PolicyActionWarn || policy.Action == models.PolicyActionFail {
				return &models.PolicyViolation{
					SBOMID:            sbom.ID,
					ComponentID:       component.ID,
					ViolationType:     models.ViolationTypeLicense,
					Severity:          mapPolicyActionToSeverity(policy.Action),
					PolicyID:          policy.ID,
					Description:       fmt.Sprintf("Component '%s@%s' has unknown license", component.Name, component.Version),
					RecommendedAction: "Review and identify the actual license for this component",
					Status:            models.ViolationStatusOpen,
					Metadata: map[string]interface{}{
						"component_name":    component.Name,
						"component_version": component.Version,
						"purl":              component.PURL,
						"reason":            description,
					},
				}
			}
		}
	}

	return nil
}

// getDefaultLicensePolicy returns a default policy for licenses not explicitly configured
func (pe *PolicyEngine) getDefaultLicensePolicy(licenseName string) *models.LicensePolicy {
	// Conservative default: warn on unknown licenses
	return &models.LicensePolicy{
		ID:          0, // Default policy
		LicenseName: licenseName,
		Action:      models.PolicyActionWarn,
		Reason:      "License not in approved list",
		IsActive:    true,
	}
}

// calculateSummary calculates violation summary statistics
func (pe *PolicyEngine) calculateSummary(licenseViolations, vulnViolations, customRuleViolations []*models.PolicyViolation) ViolationSummary {
	summary := ViolationSummary{
		LicenseViolations: len(licenseViolations),
		VulnViolations:    len(vulnViolations),
	}

	allViolations := append(licenseViolations, vulnViolations...)
	allViolations = append(allViolations, customRuleViolations...)
	summary.TotalViolations = len(allViolations)

	for _, violation := range allViolations {
		// Count by severity
		switch violation.Severity {
		case "Critical":
			summary.CriticalViolations++
		case "High":
			summary.HighViolations++
		case "Medium":
			summary.MediumViolations++
		case "Low":
			summary.LowViolations++
		}

		// Count by action type based on severity
		action := mapSeverityToPolicyAction(violation.Severity)
		switch action {
		case models.PolicyActionBlock, models.PolicyActionFail:
			summary.BlockingViolations++
		case models.PolicyActionWarn:
			summary.WarningViolations++
		}
	}

	return summary
}

// determineOverallStatus determines the overall compliance status
func (pe *PolicyEngine) determineOverallStatus(licenseViolations, vulnViolations, customRuleViolations []*models.PolicyViolation) models.PolicyAction {
	allViolations := append(licenseViolations, vulnViolations...)
	allViolations = append(allViolations, customRuleViolations...)

	hasBlocking := false
	hasWarning := false

	for _, violation := range allViolations {
		action := mapSeverityToPolicyAction(violation.Severity)
		switch action {
		case models.PolicyActionBlock, models.PolicyActionFail:
			hasBlocking = true
		case models.PolicyActionWarn:
			hasWarning = true
		}
	}

	if hasBlocking {
		return models.PolicyActionFail
	}
	if hasWarning {
		return models.PolicyActionWarn
	}

	return models.PolicyActionAllow
}

// generateRecommendations generates actionable recommendations
func (pe *PolicyEngine) generateRecommendations(result *EvaluationResult) []string {
	var recommendations []string

	if result.Summary.BlockingViolations > 0 {
		recommendations = append(recommendations, "❌ Critical issues found that must be resolved before deployment")
	}

	if result.Summary.CriticalViolations > 0 {
		recommendations = append(recommendations, fmt.Sprintf("🚨 %d critical vulnerabilities found - immediate action required", result.Summary.CriticalViolations))
	}

	if result.Summary.HighViolations > 0 {
		recommendations = append(recommendations, fmt.Sprintf("⚠️ %d high-severity issues found - prioritize for resolution", result.Summary.HighViolations))
	}

	if result.Summary.LicenseViolations > 0 {
		recommendations = append(recommendations, fmt.Sprintf("📄 %d license compliance issues found - review component licenses", result.Summary.LicenseViolations))
	}

	if result.Summary.TotalViolations == 0 {
		recommendations = append(recommendations, "✅ No policy violations found - compliance check passed")
	}

	return recommendations
}

// generateVulnRecommendation generates specific recommendations for vulnerabilities
func (pe *PolicyEngine) generateVulnRecommendation(vuln *models.Vulnerability, policy *models.VulnerabilityPolicy) string {
	if len(vuln.Fixes) > 0 {
		fixVersions := make([]string, len(vuln.Fixes))
		for i, fix := range vuln.Fixes {
			fixVersions[i] = fix.Version
		}
		return fmt.Sprintf("Update to fixed version(s): %s", strings.Join(fixVersions, ", "))
	}

	switch policy.Action {
	case models.PolicyActionBlock:
		return "This vulnerability blocks deployment - find alternative component or apply workaround"
	case models.PolicyActionFail:
		return "This vulnerability fails the build - must be resolved before release"
	case models.PolicyActionWarn:
		return "Monitor this vulnerability and apply security measures as needed"
	default:
		return "Review vulnerability and assess risk"
	}
}

// Helper functions

func normalizeLicenseName(license string) string {
	// Normalize license names for consistent matching
	license = strings.TrimSpace(license)
	license = strings.ToUpper(license)

	// Common normalizations
	normalizations := map[string]string{
		"APACHE-2.0":   "APACHE-2.0",
		"APACHE 2.0":   "APACHE-2.0",
		"APACHE V2":    "APACHE-2.0",
		"MIT LICENSE":  "MIT",
		"BSD-3-CLAUSE": "BSD-3-CLAUSE",
		"BSD 3-CLAUSE": "BSD-3-CLAUSE",
		"GPL-3.0":      "GPL-3.0",
		"GPL V3":       "GPL-3.0",
		"GPL-2.0":      "GPL-2.0",
		"GPL V2":       "GPL-2.0",
	}

	if normalized, exists := normalizations[license]; exists {
		return normalized
	}

	return license
}

func matchesLicense(policyLicense, componentLicense string) bool {
	policyLicense = normalizeLicenseName(policyLicense)
	componentLicense = normalizeLicenseName(componentLicense)

	// Exact match
	if policyLicense == componentLicense {
		return true
	}

	// Wildcard matching
	if policyLicense == "*" || policyLicense == "ANY" {
		return true
	}

	// Prefix matching for license families
	if strings.HasSuffix(policyLicense, "*") {
		prefix := strings.TrimSuffix(policyLicense, "*")
		return strings.HasPrefix(componentLicense, prefix)
	}

	return false
}

func mapPolicyActionToSeverity(action models.PolicyAction) string {
	switch action {
	case models.PolicyActionFail, models.PolicyActionBlock:
		return "Critical"
	case models.PolicyActionWarn:
		return "High"
	default:
		return "Medium"
	}
}

func mapSeverityToPolicyAction(severity string) models.PolicyAction {
	switch strings.ToLower(severity) {
	case "critical":
		return models.PolicyActionFail
	case "high":
		return models.PolicyActionBlock
	case "medium":
		return models.PolicyActionWarn
	case "low":
		return models.PolicyActionWarn
	default:
		return models.PolicyActionAllow
	}
}

// evaluateCustomRules evaluates custom rules against components and vulnerabilities
func (pe *PolicyEngine) evaluateCustomRules(sbom *models.SBOM, components []*models.Component, vulnerabilities []*models.Vulnerability) ([]*models.PolicyViolation, error) {
	var violations []*models.PolicyViolation

	// Group vulnerabilities by component
	vulnByComponent := make(map[int][]*models.Vulnerability)
	for _, vuln := range vulnerabilities {
		vulnByComponent[vuln.ComponentID] = append(vulnByComponent[vuln.ComponentID], vuln)
	}

	// Evaluate rules for each component
	for _, component := range components {
		// Component-level rules
		componentViolations, err := pe.ruleEngine.EvaluateComponent(component)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate component rules for %s: %w", component.Name, err)
		}
		for _, violation := range componentViolations {
			violation.SBOMID = sbom.ID
			violation.ComponentID = component.ID
			violations = append(violations, violation)
		}

		// License rules
		for _, license := range component.Licenses {
			licenseViolations, err := pe.ruleEngine.EvaluateLicense(license, component)
			if err != nil {
				return nil, fmt.Errorf("failed to evaluate license rules for %s: %w", license, err)
			}
			for _, violation := range licenseViolations {
				violation.SBOMID = sbom.ID
				violation.ComponentID = component.ID
				violations = append(violations, violation)
			}
		}

		// Vulnerability rules for this component
		if componentVulns, exists := vulnByComponent[component.ID]; exists {
			for _, vuln := range componentVulns {
				vulnViolations, err := pe.ruleEngine.EvaluateVulnerability(vuln, component)
				if err != nil {
					return nil, fmt.Errorf("failed to evaluate vulnerability rules for %d: %w", vuln.ID, err)
				}
				for _, violation := range vulnViolations {
					violation.SBOMID = sbom.ID
					violation.ComponentID = component.ID
					vulnID := vuln.ID
					violation.VulnerabilityID = &vulnID
					violations = append(violations, violation)
				}
			}
		}
	}

	return violations, nil
}
