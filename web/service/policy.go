package service

import (
	"encoding/json"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

type PolicyService struct {
	database *db.Database
}

func NewPolicyService(db *db.Database) *PolicyService {
	return &PolicyService{database: db}
}

func (ds *PolicyService) HandleAPILicensePolicies(c *fiber.Ctx) error {
	policies, err := ds.database.GetActiveLicensePolicies()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get license policies"})
	}
	return c.JSON(policies)
}

func (ds *PolicyService) HandleAPIVulnerabilityPolicies(c *fiber.Ctx) error {
	policies, err := ds.database.GetActiveVulnerabilityPolicies()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get vulnerability policies"})
	}
	return c.JSON(policies)
}

func (ds *PolicyService) HandleAPICreateLicensePolicy(c *fiber.Ctx) error {
	var policy models.LicensePolicy
	if err := json.Unmarshal(c.Body(), &policy); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if err := ds.database.CreateLicensePolicy(&policy); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create policy"})
	}

	return c.Status(201).JSON(policy)
}

func (ds *PolicyService) HandleAPICreateVulnerabilityPolicy(c *fiber.Ctx) error {
	var policy models.VulnerabilityPolicy
	if err := json.Unmarshal(c.Body(), &policy); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if err := ds.database.CreateVulnerabilityPolicy(&policy); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create policy"})
	}

	return c.Status(201).JSON(policy)
}

// Helper methods

// Policy management handlers
func (ds *PolicyService) HandleAPIDeleteLicensePolicy(c *fiber.Ctx) error {
	idParam := c.Params("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid policy ID"})
	}

	if err := ds.database.DeleteLicensePolicy(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete policy"})
	}

	return c.SendStatus(204)
}

func (ds *PolicyService) HandleAPIDeleteVulnerabilityPolicy(c *fiber.Ctx) error {
	idParam := c.Params("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid policy ID"})
	}

	if err := ds.database.DeleteVulnerabilityPolicy(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete policy"})
	}

	return c.SendStatus(204)
}
