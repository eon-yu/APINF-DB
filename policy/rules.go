package policy

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"oss-compliance-scanner/models"

	"gopkg.in/yaml.v3"
)

// CustomRule represents a custom policy rule
type CustomRule struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Type        string            `yaml:"type"` // license, vulnerability, component
	Enabled     bool              `yaml:"enabled"`
	Severity    string            `yaml:"severity"` // critical, high, medium, low
	Action      string            `yaml:"action"`   // block, warn, allow
	Conditions  []RuleCondition   `yaml:"conditions"`
	Metadata    map[string]string `yaml:"metadata"`
}

// RuleCondition represents a condition within a rule
type RuleCondition struct {
	Field    string `yaml:"field"`    // license, severity, component_name, etc.
	Operator string `yaml:"operator"` // equals, contains, matches, greater_than, etc.
	Value    string `yaml:"value"`
	Negate   bool   `yaml:"negate"`
}

// RuleSet represents a collection of custom rules
type RuleSet struct {
	Version     string                 `yaml:"version"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Rules       []CustomRule           `yaml:"rules"`
	Globals     map[string]interface{} `yaml:"globals"`
}

// RuleEngine manages and evaluates custom rules
type RuleEngine struct {
	ruleSets []RuleSet
	globals  map[string]interface{}
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		ruleSets: make([]RuleSet, 0),
		globals:  make(map[string]interface{}),
	}
}

// LoadRulesFromFile loads rules from a YAML file
func (re *RuleEngine) LoadRulesFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read rules file %s: %w", filePath, err)
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return fmt.Errorf("failed to parse rules file %s: %w", filePath, err)
	}

	// Validate rules
	if err := re.validateRuleSet(&ruleSet); err != nil {
		return fmt.Errorf("invalid rules in %s: %w", filePath, err)
	}

	re.ruleSets = append(re.ruleSets, ruleSet)

	// Merge globals
	for key, value := range ruleSet.Globals {
		re.globals[key] = value
	}

	return nil
}

// LoadRulesFromString loads rules from a YAML string
func (re *RuleEngine) LoadRulesFromString(yamlContent string) error {
	var ruleSet RuleSet
	if err := yaml.Unmarshal([]byte(yamlContent), &ruleSet); err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	if err := re.validateRuleSet(&ruleSet); err != nil {
		return fmt.Errorf("invalid rules: %w", err)
	}

	re.ruleSets = append(re.ruleSets, ruleSet)
	return nil
}

// EvaluateComponent evaluates rules against a component
func (re *RuleEngine) EvaluateComponent(component *models.Component) ([]*models.PolicyViolation, error) {
	var violations []*models.PolicyViolation

	for _, ruleSet := range re.ruleSets {
		for _, rule := range ruleSet.Rules {
			if !rule.Enabled || rule.Type != "component" {
				continue
			}

			if matches, err := re.evaluateRuleConditions(rule.Conditions, component, nil, nil); err != nil {
				return nil, fmt.Errorf("failed to evaluate rule %s: %w", rule.ID, err)
			} else if matches {
				violation := &models.PolicyViolation{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					Type:        models.ViolationType(rule.Type),
					Severity:    rule.Severity,
					Action:      models.PolicyAction(rule.Action),
					Description: rule.Description,
					Component:   component.Name + "@" + component.Version,
					Details:     fmt.Sprintf("Component %s@%s matches rule %s", component.Name, component.Version, rule.Name),
				}
				violations = append(violations, violation)
			}
		}
	}

	return violations, nil
}

// EvaluateLicense evaluates rules against a license
func (re *RuleEngine) EvaluateLicense(license string, component *models.Component) ([]*models.PolicyViolation, error) {
	var violations []*models.PolicyViolation

	for _, ruleSet := range re.ruleSets {
		for _, rule := range ruleSet.Rules {
			if !rule.Enabled || rule.Type != "license" {
				continue
			}

			// Create a mock license object for evaluation
			licenseData := map[string]interface{}{
				"license": license,
			}

			if matches, err := re.evaluateRuleConditionsMap(rule.Conditions, licenseData, component, nil); err != nil {
				return nil, fmt.Errorf("failed to evaluate license rule %s: %w", rule.ID, err)
			} else if matches {
				violation := &models.PolicyViolation{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					Type:        models.ViolationType(rule.Type),
					Severity:    rule.Severity,
					Action:      models.PolicyAction(rule.Action),
					Description: rule.Description,
					Component:   component.Name + "@" + component.Version,
					Details:     fmt.Sprintf("License %s violates rule %s", license, rule.Name),
				}
				violations = append(violations, violation)
			}
		}
	}

	return violations, nil
}

// EvaluateVulnerability evaluates rules against a vulnerability
func (re *RuleEngine) EvaluateVulnerability(vuln *models.Vulnerability, component *models.Component) ([]*models.PolicyViolation, error) {
	var violations []*models.PolicyViolation

	for _, ruleSet := range re.ruleSets {
		for _, rule := range ruleSet.Rules {
			if !rule.Enabled || rule.Type != "vulnerability" {
				continue
			}

			if matches, err := re.evaluateRuleConditions(rule.Conditions, component, vuln, nil); err != nil {
				return nil, fmt.Errorf("failed to evaluate vulnerability rule %s: %w", rule.ID, err)
			} else if matches {
				violation := &models.PolicyViolation{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					Type:        models.ViolationType(rule.Type),
					Severity:    rule.Severity,
					Action:      models.PolicyAction(rule.Action),
					Description: rule.Description,
					Component:   component.Name + "@" + component.Version,
					Details:     fmt.Sprintf("Vulnerability %s violates rule %s", vuln.ID, rule.Name),
				}
				violations = append(violations, violation)
			}
		}
	}

	return violations, nil
}

// evaluateRuleConditions evaluates a set of rule conditions
func (re *RuleEngine) evaluateRuleConditions(conditions []RuleCondition, component *models.Component, vuln *models.Vulnerability, extra map[string]interface{}) (bool, error) {
	// All conditions must match (AND logic)
	for _, condition := range conditions {
		matches, err := re.evaluateCondition(condition, component, vuln, extra)
		if err != nil {
			return false, err
		}

		if condition.Negate {
			matches = !matches
		}

		if !matches {
			return false, nil
		}
	}

	return true, nil
}

// evaluateRuleConditionsMap evaluates conditions against a map of data
func (re *RuleEngine) evaluateRuleConditionsMap(conditions []RuleCondition, data map[string]interface{}, component *models.Component, vuln *models.Vulnerability) (bool, error) {
	for _, condition := range conditions {
		matches, err := re.evaluateConditionMap(condition, data, component, vuln)
		if err != nil {
			return false, err
		}

		if condition.Negate {
			matches = !matches
		}

		if !matches {
			return false, nil
		}
	}

	return true, nil
}

// evaluateCondition evaluates a single condition
func (re *RuleEngine) evaluateCondition(condition RuleCondition, component *models.Component, vuln *models.Vulnerability, extra map[string]interface{}) (bool, error) {
	fieldValue, err := re.getFieldValue(condition.Field, component, vuln, extra)
	if err != nil {
		return false, err
	}

	return re.applyOperator(condition.Operator, fieldValue, condition.Value)
}

// evaluateConditionMap evaluates a condition against a map
func (re *RuleEngine) evaluateConditionMap(condition RuleCondition, data map[string]interface{}, component *models.Component, vuln *models.Vulnerability) (bool, error) {
	var fieldValue interface{}

	if value, exists := data[condition.Field]; exists {
		fieldValue = value
	} else {
		// Fallback to component/vulnerability fields
		var err error
		fieldValue, err = re.getFieldValue(condition.Field, component, vuln, data)
		if err != nil {
			return false, err
		}
	}

	return re.applyOperator(condition.Operator, fieldValue, condition.Value)
}

// getFieldValue extracts a field value from component, vulnerability, or extra data
func (re *RuleEngine) getFieldValue(field string, component *models.Component, vuln *models.Vulnerability, extra map[string]interface{}) (interface{}, error) {
	// Check extra data first
	if extra != nil {
		if value, exists := extra[field]; exists {
			return value, nil
		}
	}

	// Component fields
	if component != nil {
		switch field {
		case "component_name", "name":
			return component.Name, nil
		case "component_version", "version":
			return component.Version, nil
		case "component_type", "type":
			return component.Type, nil
		case "language":
			return component.Language, nil
		case "purl":
			return component.PURL, nil
		case "cpe":
			return component.CPE, nil
		}
	}

	// Vulnerability fields
	if vuln != nil {
		switch field {
		case "vulnerability_id", "vuln_id", "cve":
			return vuln.ID, nil
		case "severity":
			return vuln.Severity, nil
		case "cvss_score":
			return vuln.CVSSScore, nil
		case "description":
			return vuln.Description, nil
		case "fixed_version":
			return vuln.FixedVersion, nil
		}
	}

	return nil, fmt.Errorf("unknown field: %s", field)
}

// applyOperator applies an operator to compare field value with rule value
func (re *RuleEngine) applyOperator(operator string, fieldValue interface{}, ruleValue string) (bool, error) {
	fieldStr := fmt.Sprintf("%v", fieldValue)

	switch operator {
	case "equals", "eq":
		return fieldStr == ruleValue, nil

	case "not_equals", "neq":
		return fieldStr != ruleValue, nil

	case "contains":
		return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(ruleValue)), nil

	case "not_contains":
		return !strings.Contains(strings.ToLower(fieldStr), strings.ToLower(ruleValue)), nil

	case "starts_with":
		return strings.HasPrefix(strings.ToLower(fieldStr), strings.ToLower(ruleValue)), nil

	case "ends_with":
		return strings.HasSuffix(strings.ToLower(fieldStr), strings.ToLower(ruleValue)), nil

	case "matches", "regex":
		matched, err := regexp.MatchString(ruleValue, fieldStr)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern %s: %w", ruleValue, err)
		}
		return matched, nil

	case "greater_than", "gt":
		fieldNum, err := re.toFloat64(fieldValue)
		if err != nil {
			return false, fmt.Errorf("cannot convert field value to number: %w", err)
		}
		ruleNum, err := strconv.ParseFloat(ruleValue, 64)
		if err != nil {
			return false, fmt.Errorf("cannot convert rule value to number: %w", err)
		}
		return fieldNum > ruleNum, nil

	case "greater_equal", "gte":
		fieldNum, err := re.toFloat64(fieldValue)
		if err != nil {
			return false, fmt.Errorf("cannot convert field value to number: %w", err)
		}
		ruleNum, err := strconv.ParseFloat(ruleValue, 64)
		if err != nil {
			return false, fmt.Errorf("cannot convert rule value to number: %w", err)
		}
		return fieldNum >= ruleNum, nil

	case "less_than", "lt":
		fieldNum, err := re.toFloat64(fieldValue)
		if err != nil {
			return false, fmt.Errorf("cannot convert field value to number: %w", err)
		}
		ruleNum, err := strconv.ParseFloat(ruleValue, 64)
		if err != nil {
			return false, fmt.Errorf("cannot convert rule value to number: %w", err)
		}
		return fieldNum < ruleNum, nil

	case "less_equal", "lte":
		fieldNum, err := re.toFloat64(fieldValue)
		if err != nil {
			return false, fmt.Errorf("cannot convert field value to number: %w", err)
		}
		ruleNum, err := strconv.ParseFloat(ruleValue, 64)
		if err != nil {
			return false, fmt.Errorf("cannot convert rule value to number: %w", err)
		}
		return fieldNum <= ruleNum, nil

	case "in":
		values := strings.Split(ruleValue, ",")
		for _, value := range values {
			if strings.TrimSpace(value) == fieldStr {
				return true, nil
			}
		}
		return false, nil

	case "not_in":
		values := strings.Split(ruleValue, ",")
		for _, value := range values {
			if strings.TrimSpace(value) == fieldStr {
				return false, nil
			}
		}
		return true, nil

	default:
		return false, fmt.Errorf("unknown operator: %s", operator)
	}
}

// toFloat64 converts various types to float64
func (re *RuleEngine) toFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

// validateRuleSet validates a rule set
func (re *RuleEngine) validateRuleSet(ruleSet *RuleSet) error {
	if ruleSet.Version == "" {
		return fmt.Errorf("rule set version is required")
	}

	if len(ruleSet.Rules) == 0 {
		return fmt.Errorf("rule set must contain at least one rule")
	}

	for i, rule := range ruleSet.Rules {
		if err := re.validateRule(&rule); err != nil {
			return fmt.Errorf("rule %d (%s): %w", i, rule.ID, err)
		}
	}

	return nil
}

// validateRule validates a single rule
func (re *RuleEngine) validateRule(rule *CustomRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}

	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}

	validTypes := []string{"license", "vulnerability", "component"}
	if !re.isValidValue(rule.Type, validTypes) {
		return fmt.Errorf("invalid rule type: %s, must be one of %v", rule.Type, validTypes)
	}

	validSeverities := []string{"critical", "high", "medium", "low"}
	if !re.isValidValue(rule.Severity, validSeverities) {
		return fmt.Errorf("invalid severity: %s, must be one of %v", rule.Severity, validSeverities)
	}

	validActions := []string{"block", "warn", "allow"}
	if !re.isValidValue(rule.Action, validActions) {
		return fmt.Errorf("invalid action: %s, must be one of %v", rule.Action, validActions)
	}

	if len(rule.Conditions) == 0 {
		return fmt.Errorf("rule must contain at least one condition")
	}

	for i, condition := range rule.Conditions {
		if err := re.validateCondition(&condition); err != nil {
			return fmt.Errorf("condition %d: %w", i, err)
		}
	}

	return nil
}

// validateCondition validates a rule condition
func (re *RuleEngine) validateCondition(condition *RuleCondition) error {
	if condition.Field == "" {
		return fmt.Errorf("condition field is required")
	}

	if condition.Operator == "" {
		return fmt.Errorf("condition operator is required")
	}

	validOperators := []string{
		"equals", "eq", "not_equals", "neq",
		"contains", "not_contains", "starts_with", "ends_with",
		"matches", "regex", "greater_than", "gt", "greater_equal", "gte",
		"less_than", "lt", "less_equal", "lte", "in", "not_in",
	}
	if !re.isValidValue(condition.Operator, validOperators) {
		return fmt.Errorf("invalid operator: %s, must be one of %v", condition.Operator, validOperators)
	}

	return nil
}

// isValidValue checks if a value is in a list of valid values
func (re *RuleEngine) isValidValue(value string, validValues []string) bool {
	for _, valid := range validValues {
		if value == valid {
			return true
		}
	}
	return false
}

// GetAllRules returns all loaded rules
func (re *RuleEngine) GetAllRules() []CustomRule {
	var allRules []CustomRule
	for _, ruleSet := range re.ruleSets {
		allRules = append(allRules, ruleSet.Rules...)
	}
	return allRules
}

// GetRuleByID returns a rule by its ID
func (re *RuleEngine) GetRuleByID(id string) (*CustomRule, error) {
	for _, ruleSet := range re.ruleSets {
		for _, rule := range ruleSet.Rules {
			if rule.ID == id {
				return &rule, nil
			}
		}
	}
	return nil, fmt.Errorf("rule not found: %s", id)
}
