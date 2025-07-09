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
	ID          int          `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	LicenseName string       `json:"license_name" gorm:"column:license_name"`
	Action      PolicyAction `json:"action" gorm:"column:action"`
	Reason      string       `json:"reason" gorm:"column:reason"`
	IsActive    bool         `json:"is_active" gorm:"column:is_active"`
	CreatedAt   time.Time    `json:"created_at" gorm:"column:created_at"`
	UpdatedAt   time.Time    `json:"updated_at" gorm:"column:updated_at"`
}

// VulnerabilityPolicy represents vulnerability policy settings
type VulnerabilityPolicy struct {
	ID                 int          `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	MinSeverityLevel   string       `json:"min_severity_level" gorm:"column:min_severity_level"`
	MaxCVSSScore       float64      `json:"max_cvss_score" gorm:"column:max_cvss_score"`
	Action             PolicyAction `json:"action" gorm:"column:action"`
	IgnoreFixAvailable bool         `json:"ignore_fix_available" gorm:"column:ignore_fix_available"`
	GracePeriodDays    int          `json:"grace_period_days" gorm:"column:grace_period_days"`
	IsActive           bool         `json:"is_active" gorm:"column:is_active"`
	CreatedAt          time.Time    `json:"created_at" gorm:"column:created_at"`
	UpdatedAt          time.Time    `json:"updated_at" gorm:"column:updated_at"`
}

// PolicyViolation represents a policy violation found during scan
type PolicyViolation struct {
	ID                int                    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	SBOMID            int                    `json:"sbom_id" gorm:"column:sbom_id"`
	ComponentID       int                    `json:"component_id" gorm:"column:component_id"`
	VulnerabilityID   *int                   `json:"vulnerability_id" gorm:"column:vulnerability_id"`
	ViolationType     ViolationType          `json:"violation_type" gorm:"column:violation_type"`
	Severity          string                 `json:"severity" gorm:"column:severity"`
	PolicyID          int                    `json:"policy_id" gorm:"column:policy_id"`
	Description       string                 `json:"description" gorm:"column:description"`
	RecommendedAction string                 `json:"recommended_action" gorm:"column:recommended_action"`
	Status            ViolationStatus        `json:"status" gorm:"column:status"`
	Metadata          map[string]interface{} `json:"metadata" gorm:"-"`
	MetadataJSON      string                 `json:"-" gorm:"column:metadata_json"`
	CreatedAt         time.Time              `json:"created_at" gorm:"column:created_at"`
	UpdatedAt         time.Time              `json:"updated_at" gorm:"column:updated_at"`
	ResolvedAt        *time.Time             `json:"resolved_at" gorm:"column:resolved_at"`
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
	SlackEnabled         bool   `json:"slack_enabled"`
	EmailSMTP            string `json:"email_smtp"`
	EmailPort            int    `json:"email_port"`
	EmailRecipients      string `json:"email_recipients"`
	EmailEnabled         bool   `json:"email_enabled"`
	NotifyOnViolation    bool   `json:"notify_on_violation"`
	NotifyOnResolution   bool   `json:"notify_on_resolution"`
	MinSeverityLevel     string `json:"min_severity_level"`
	NotificationBatching bool   `json:"notification_batching"`
	BatchingInterval     int    `json:"batching_interval_minutes"`
}

// ScanResult represents the overall result of a compliance scan
type ScanResult struct {
	ID                   int                    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	SBOMID               int                    `json:"sbom_id" gorm:"column:sbom_id"`
	RepoName             string                 `json:"repo_name" gorm:"column:repo_name"`
	ModulePath           string                 `json:"module_path" gorm:"column:module_path"`
	ScanStartTime        time.Time              `json:"scan_start_time" gorm:"column:scan_start_time"`
	ScanEndTime          time.Time              `json:"scan_end_time" gorm:"column:scan_end_time"`
	Status               ScanStatus             `json:"status" gorm:"column:status"`
	TotalComponents      int                    `json:"total_components" gorm:"column:total_components"`
	VulnerabilitiesFound int                    `json:"vulnerabilities_found" gorm:"column:vulnerabilities_found"`
	LicenseViolations    int                    `json:"license_violations" gorm:"column:license_violations"`
	CriticalVulns        int                    `json:"critical_vulns" gorm:"column:critical_vulns"`
	HighVulns            int                    `json:"high_vulns" gorm:"column:high_vulns"`
	MediumVulns          int                    `json:"medium_vulns" gorm:"column:medium_vulns"`
	LowVulns             int                    `json:"low_vulns" gorm:"column:low_vulns"`
	OverallRisk          RiskLevel              `json:"overall_risk" gorm:"column:overall_risk"`
	Metadata             map[string]interface{} `json:"metadata" gorm:"-"`
	MetadataJSON         string                 `json:"-" gorm:"column:metadata_json"`
	CreatedAt            time.Time              `json:"created_at" gorm:"column:created_at"`
	UpdatedAt            time.Time              `json:"updated_at" gorm:"column:updated_at"`
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
