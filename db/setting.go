package db

import (
	"oss-compliance-scanner/config"
	"oss-compliance-scanner/models"
)

func (db *Database) GetSettings() (*models.Setting, error) {
	setting := &models.Setting{}
	err := db.orm.Model(&models.Setting{}).First(&setting).Error
	if err != nil {
		setting = initSettings()
		err = db.orm.Model(&models.Setting{}).Create(&setting).Error
		if err != nil {
			return nil, err
		}
	}
	return setting, nil
}

func (db *Database) UpdateSettings(setting *models.Setting) error {
	return db.orm.Model(&models.Setting{}).Save(setting).Error
}

func initSettings() *models.Setting {
	cfg := config.GetConfig()
	settings := &models.Setting{
		AppName:                "OSS Compliance Scanner",
		AppVersion:             cfg.AppVersion,
		LogLevel:               cfg.Logging.Level,
		Timezone:               cfg.Timezone,
		Language:               cfg.Language,
		AutoUpdate:             true,
		SyftTimeout:            300,
		SyftOutputFormat:       "json",
		SyftIncludeDevDeps:     true,
		GrypeTimeout:           600,
		GrypeFailOn:            "high",
		GrypeUpdateDB:          true,
		SlackWebhookURL:        cfg.Notification.SlackWebhookURL,
		SlackChannel:           cfg.Notification.SlackChannel,
		SlackEnabled:           cfg.Notification.SlackEnabled,
		EmailSMTP:              cfg.Notification.EmailSMTP,
		EmailPort:              cfg.Notification.EmailPort,
		EmailRecipients:        cfg.Notification.EmailRecipients,
		EmailEnabled:           cfg.Notification.EmailEnabled,
		NotifyCritical:         true,
		NotifyHigh:             true,
		NotifyLicenseViolation: true,
		NotifyScanFailure:      false,
		SessionTimeout:         30,
		MaxLoginAttempts:       5,
		RequireMFA:             false,
		APIRateLimit:           100,
		EnableCors:             true,
		EnableAuditLog:         true,
		LogRetentionDays:       30,
	}
	return settings
}
