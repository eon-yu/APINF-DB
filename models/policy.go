package models

import (
	"encoding/json"
	"time"
)

// PolicyAction represents actions to take when policy violation occurs
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionWarn  PolicyAction = "warn"
	PolicyActionBlock PolicyAction = "block"
	PolicyActionFail  PolicyAction = "fail"
)

// LicensePolicy represents license compliance policy
type LicensePolicy struct {
	ID          int          `json:"id" db:"id"`
	LicenseName string       `json:"license_name" db:"license_name"`
	Action      PolicyAction `json:"action" db:"action"`
	Reason      string       `json:"reason" db:"reason"`
	IsActive    bool         `json:"is_active" db:"is_active"`
	CreatedAt   time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at" db:"updated_at"`
}

// VulnerabilityPolicy represents vulnerability policy settings
type VulnerabilityPolicy struct {
	ID                 int          `json:"id" db:"id"`
	MinSeverityLevel   string       `json:"min_severity_level" db:"min_severity_level"`
	MaxCVSSScore       float64      `json:"max_cvss_score" db:"max_cvss_score"`
	Action             PolicyAction `json:"action" db:"action"`
	IgnoreFixAvailable bool         `json:"ignore_fix_available" db:"ignore_fix_available"`
	GracePeriodDays    int          `json:"grace_period_days" db:"grace_period_days"`
	IsActive           bool         `json:"is_active" db:"is_active"`
	CreatedAt          time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at" db:"updated_at"`
}

// PolicyViolation represents a policy violation found during scan
type PolicyViolation struct {
	ID                int                    `json:"id" db:"id"`
	SBOMID            int                    `json:"sbom_id" db:"sbom_id"`
	ComponentID       int                    `json:"component_id" db:"component_id"`
	VulnerabilityID   *int                   `json:"vulnerability_id" db:"vulnerability_id"`
	ViolationType     ViolationType          `json:"violation_type" db:"violation_type"`
	Severity          string                 `json:"severity" db:"severity"`
	PolicyID          int                    `json:"policy_id" db:"policy_id"`
	Description       string                 `json:"description" db:"description"`
	RecommendedAction string                 `json:"recommended_action" db:"recommended_action"`
	Status            ViolationStatus        `json:"status" db:"status"`
	Metadata          map[string]interface{} `json:"metadata" db:"-"`
	MetadataJSON      string                 `json:"-" db:"metadata_json"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
	ResolvedAt        *time.Time             `json:"resolved_at" db:"resolved_at"`
}

// ViolationType represents the type of policy violation
type ViolationType string

const (
	ViolationTypeLicense       ViolationType = "license"
	ViolationTypeVulnerability ViolationType = "vulnerability"
)

// ViolationStatus represents the current status of a violation
type ViolationStatus string

const (
	ViolationStatusOpen          ViolationStatus = "open"
	ViolationStatusIgnored       ViolationStatus = "ignored"
	ViolationStatusResolved      ViolationStatus = "resolved"
	ViolationStatusFalsePositive ViolationStatus = "false_positive"
)

// PolicyConfig represents the overall policy configuration
type PolicyConfig struct {
	LicensePolicies       []LicensePolicy       `json:"license_policies"`
	VulnerabilityPolicies []VulnerabilityPolicy `json:"vulnerability_policies"`
	GlobalSettings        GlobalPolicySettings  `json:"global_settings"`
}

// GlobalPolicySettings represents global policy settings
type GlobalPolicySettings struct {
	EnableLicenseCheck       bool                 `json:"enable_license_check"`
	EnableVulnerabilityCheck bool                 `json:"enable_vulnerability_check"`
	IgnoredPackages          []string             `json:"ignored_packages"`
	TrustedRegistries        []string             `json:"trusted_registries"`
	ScanTimeout              int                  `json:"scan_timeout_minutes"`
	MaxParallelScans         int                  `json:"max_parallel_scans"`
	NotificationSettings     NotificationSettings `json:"notification_settings"`
}

// NotificationSettings represents notification configuration
type NotificationSettings struct {
	SlackWebhookURL      string `json:"slack_webhook_url"`
	SlackChannel         string `json:"slack_channel"`
	NotifyOnViolation    bool   `json:"notify_on_violation"`
	NotifyOnResolution   bool   `json:"notify_on_resolution"`
	MinSeverityLevel     string `json:"min_severity_level"`
	NotificationBatching bool   `json:"notification_batching"`
	BatchingInterval     int    `json:"batching_interval_minutes"`
}

// ScanResult represents the overall result of a compliance scan
type ScanResult struct {
	ID                   int                    `json:"id" db:"id"`
	SBOMID               int                    `json:"sbom_id" db:"sbom_id"`
	RepoName             string                 `json:"repo_name" db:"repo_name"`
	ModulePath           string                 `json:"module_path" db:"module_path"`
	ScanStartTime        time.Time              `json:"scan_start_time" db:"scan_start_time"`
	ScanEndTime          time.Time              `json:"scan_end_time" db:"scan_end_time"`
	Status               ScanStatus             `json:"status" db:"status"`
	TotalComponents      int                    `json:"total_components" db:"total_components"`
	VulnerabilitiesFound int                    `json:"vulnerabilities_found" db:"vulnerabilities_found"`
	LicenseViolations    int                    `json:"license_violations" db:"license_violations"`
	CriticalVulns        int                    `json:"critical_vulns" db:"critical_vulns"`
	HighVulns            int                    `json:"high_vulns" db:"high_vulns"`
	MediumVulns          int                    `json:"medium_vulns" db:"medium_vulns"`
	LowVulns             int                    `json:"low_vulns" db:"low_vulns"`
	OverallRisk          RiskLevel              `json:"overall_risk" db:"overall_risk"`
	Metadata             map[string]interface{} `json:"metadata" db:"-"`
	MetadataJSON         string                 `json:"-" db:"metadata_json"`
	CreatedAt            time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at" db:"updated_at"`
}

// ScanStatus represents the status of a scan
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

// RiskLevel represents the overall risk level
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// MarshalPolicyViolationFields marshals map fields to JSON for database storage
func (pv *PolicyViolation) MarshalPolicyViolationFields() error {
	if len(pv.Metadata) > 0 {
		metadataJSON, err := json.Marshal(pv.Metadata)
		if err != nil {
			return err
		}
		pv.MetadataJSON = string(metadataJSON)
	}
	return nil
}

// UnmarshalPolicyViolationFields unmarshals JSON fields back to maps
func (pv *PolicyViolation) UnmarshalPolicyViolationFields() error {
	if pv.MetadataJSON != "" {
		if err := json.Unmarshal([]byte(pv.MetadataJSON), &pv.Metadata); err != nil {
			return err
		}
	}
	return nil
}

// MarshalScanResultFields marshals map fields to JSON for database storage
func (sr *ScanResult) MarshalScanResultFields() error {
	if len(sr.Metadata) > 0 {
		metadataJSON, err := json.Marshal(sr.Metadata)
		if err != nil {
			return err
		}
		sr.MetadataJSON = string(metadataJSON)
	}
	return nil
}

// UnmarshalScanResultFields unmarshals JSON fields back to maps
func (sr *ScanResult) UnmarshalScanResultFields() error {
	if sr.MetadataJSON != "" {
		if err := json.Unmarshal([]byte(sr.MetadataJSON), &sr.Metadata); err != nil {
			return err
		}
	}
	return nil
}

// CalculateOverallRisk calculates overall risk level based on vulnerability counts
func (sr *ScanResult) CalculateOverallRisk() RiskLevel {
	if sr.CriticalVulns > 0 {
		return RiskLevelCritical
	}
	if sr.HighVulns > 0 || sr.LicenseViolations > 0 {
		return RiskLevelHigh
	}
	if sr.MediumVulns > 0 {
		return RiskLevelMedium
	}
	return RiskLevelLow
}
