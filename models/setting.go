package models

import "time"

type Setting struct {
	ID                     int       `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	AppName                string    `json:"app_name" gorm:"column:app_name"`
	AppVersion             string    `json:"app_version" gorm:"column:app_version"`
	LogLevel               string    `json:"log_level" gorm:"column:log_level"`
	Timezone               string    `json:"timezone" gorm:"column:timezone"`
	Language               string    `json:"language" gorm:"column:language"`
	AutoUpdate             bool      `json:"auto_update" gorm:"column:auto_update"`
	SyftTimeout            int       `json:"syft_timeout" gorm:"column:syft_timeout"`
	SyftOutputFormat       string    `json:"syft_output_format" gorm:"column:syft_output_format"`
	SyftIncludeDevDeps     bool      `json:"syft_include_dev_deps" gorm:"column:syft_include_dev_deps"`
	GrypeTimeout           int       `json:"grype_timeout" gorm:"column:grype_timeout"`
	GrypeFailOn            string    `json:"grype_fail_on" gorm:"column:grype_fail_on"`
	GrypeUpdateDB          bool      `json:"grype_update_db" gorm:"column:grype_update_db"`
	SlackWebhookURL        string    `json:"slack_webhook_url" gorm:"column:slack_webhook_url"`
	SlackChannel           string    `json:"slack_channel" gorm:"column:slack_channel"`
	SlackEnabled           bool      `json:"slack_enabled" gorm:"column:slack_enabled"`
	EmailSMTP              string    `json:"email_smtp" gorm:"column:email_smtp"`
	EmailPort              int       `json:"email_port" gorm:"column:email_port"`
	EmailRecipients        string    `json:"email_recipients" gorm:"column:email_recipients"`
	EmailEnabled           bool      `json:"email_enabled" gorm:"column:email_enabled"`
	NotifyCritical         bool      `json:"notify_critical" gorm:"column:notify_critical"`
	NotifyHigh             bool      `json:"notify_high" gorm:"column:notify_high"`
	NotifyLicenseViolation bool      `json:"notify_license_violation" gorm:"column:notify_license_violation"`
	NotifyScanFailure      bool      `json:"notify_scan_failure" gorm:"column:notify_scan_failure"`
	SessionTimeout         int       `json:"session_timeout" gorm:"column:session_timeout"`
	MaxLoginAttempts       int       `json:"max_login_attempts" gorm:"column:max_login_attempts"`
	RequireMFA             bool      `json:"require_mfa" gorm:"column:require_mfa"`
	APIRateLimit           int       `json:"api_rate_limit" gorm:"column:api_rate_limit"`
	EnableCors             bool      `json:"enable_cors" gorm:"column:enable_cors"`
	EnableAuditLog         bool      `json:"enable_audit_log" gorm:"column:enable_audit_log"`
	LogRetentionDays       int       `json:"log_retention_days" gorm:"column:log_retention_days"`
	CreatedAt              time.Time `json:"created_at" gorm:"column:created_at"`
	UpdatedAt              time.Time `json:"updated_at" gorm:"column:updated_at"`
}
