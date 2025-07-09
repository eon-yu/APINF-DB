package service

import (
	"encoding/json"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"

	"github.com/gofiber/fiber/v2"
)

type SettingService struct {
	db *db.Database
}

func NewSettingService(db *db.Database) *SettingService {
	return &SettingService{db: db}
}

func (s *SettingService) GetSettings(c *fiber.Ctx) error {
	settings, err := s.db.GetSettings()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get settings"})
	}

	return c.JSON(settings)
}

func (ds *SettingService) PutSettings(c *fiber.Ctx) error {
	var settings models.Setting
	if err := json.Unmarshal(c.Body(), &settings); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid settings format"})
	}

	err := ds.db.UpdateSettings(&settings)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to update settings"})
	}

	return c.JSON(fiber.Map{"status": "settings updated"})
}
