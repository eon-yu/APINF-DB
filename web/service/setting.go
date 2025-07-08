package service

import (
	"encoding/json"
	"oss-compliance-scanner/db"

	"github.com/gofiber/fiber/v2"
)

type SettingService struct {
	database *db.Database
}

func NewSettingService(db *db.Database) *SettingService {
	return &SettingService{database: db}
}

func (ds *SettingService) HandleAPIGetSettings(c *fiber.Ctx) error {
	// Return default settings for now
	settings := map[string]interface{}{
		"app_name":                 "OSS Compliance Scanner",
		"app_version":              "1.0.0",
		"log_level":                "info",
		"timezone":                 "Asia/Seoul",
		"language":                 "ko",
		"auto_update":              true,
		"syft_timeout":             300,
		"syft_output_format":       "json",
		"syft_include_dev_deps":    true,
		"grype_timeout":            600,
		"grype_fail_on":            "high",
		"grype_update_db":          true,
		"slack_webhook":            "",
		"slack_channel":            "",
		"slack_enabled":            false,
		"email_smtp":               "",
		"email_port":               587,
		"email_recipients":         "",
		"email_enabled":            false,
		"notify_critical":          true,
		"notify_high":              true,
		"notify_license_violation": true,
		"notify_scan_failure":      false,
		"session_timeout":          30,
		"max_login_attempts":       5,
		"require_mfa":              false,
		"api_rate_limit":           100,
		"enable_cors":              true,
		"enable_audit_log":         true,
		"log_retention_days":       30,
	}

	return c.JSON(settings)
}

func (ds *SettingService) HandleAPIPutSettings(c *fiber.Ctx) error {
	var settings map[string]interface{}
	if err := json.Unmarshal(c.Body(), &settings); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid settings format"})
	}

	// In a real implementation, you would save these settings to a database or config file
	// For now, just return success
	return c.JSON(fiber.Map{"status": "settings updated"})
}
