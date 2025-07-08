package service

import (
	"oss-compliance-scanner/db"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

type VulnerabilityService struct {
	database *db.Database
}

func NewVulnerabilityService(db *db.Database) *VulnerabilityService {
	return &VulnerabilityService{database: db}
}

func (ds *VulnerabilityService) HandleAPIVulnerabilities(c *fiber.Ctx) error {
	sbomIDParam := c.Params("id")
	if sbomIDParam != "" {
		// Get vulnerabilities for specific SBOM
		sbomID, err := strconv.Atoi(sbomIDParam)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
		}

		// Use the new function that includes component information
		vulnerabilities, err := ds.database.GetVulnerabilitiesBySBOM(sbomID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to get vulnerabilities"})
		}

		return c.JSON(vulnerabilities)
	}

	// Get all vulnerabilities
	limit := c.QueryInt("limit", 100)
	vulnerabilities, err := ds.database.GetAllVulnerabilities(limit)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get vulnerabilities"})
	}

	return c.JSON(vulnerabilities)
}

func (ds *VulnerabilityService) HandleAPIViolations(c *fiber.Ctx) error {
	// This would require violation tracking in the database
	return c.JSON([]interface{}{})
}
func (ds *VulnerabilityService) HandleAPIResolveViolation(c *fiber.Ctx) error {
	idParam := c.Params("id")
	_, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid violation ID"})
	}

	// This would require violation tracking in the database
	// For now, return success
	return c.JSON(fiber.Map{"status": "resolved"})
}

func (ds *VulnerabilityService) HandleAPIIgnoreViolation(c *fiber.Ctx) error {
	idParam := c.Params("id")
	_, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid violation ID"})
	}

	// This would require violation tracking in the database
	// For now, return success
	return c.JSON(fiber.Map{"status": "ignored"})
}
