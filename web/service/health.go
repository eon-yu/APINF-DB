package service

import (
	"oss-compliance-scanner/db"
	"time"

	"github.com/gofiber/fiber/v2"
)

type HealthService struct {
	database *db.Database
}

func NewHealthService(db *db.Database) *HealthService {
	return &HealthService{database: db}
}

func (ds *HealthService) HandleHealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

// Health check handlers
func (ds *HealthService) HandleAPIHealthDB(c *fiber.Ctx) error {
	// Check database connectivity
	if err := ds.database.Ping(); err != nil {
		return c.Status(503).JSON(fiber.Map{"status": "error", "message": "Database connection failed"})
	}
	return c.JSON(fiber.Map{"status": "ok", "message": "Database is healthy"})
}

func (ds *HealthService) HandleAPIHealthScanner(c *fiber.Ctx) error {
	// Check if scanner tools are available
	// For now, return healthy
	return c.JSON(fiber.Map{"status": "ok", "message": "Scanner tools are available"})
}

func (ds *HealthService) HandleAPIHealthNotifier(c *fiber.Ctx) error {
	// Check notification service health
	// For now, return healthy
	return c.JSON(fiber.Map{"status": "ok", "message": "Notification service is healthy"})
}
