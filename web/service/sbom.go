package service

import (
	"fmt"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"sort"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

type SBOMService struct {
	database *db.Database
}

func NewSBOMService(db *db.Database) *SBOMService {
	return &SBOMService{database: db}
}

func (ds *SBOMService) HandleAPISBOMs(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 50)
	sboms, err := ds.database.GetAllSBOMs(limit)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get SBOMs"})
	}
	return c.JSON(sboms)
}

func (ds *SBOMService) HandleAPISBOMDetail(c *fiber.Ctx) error {
	idParam := c.Params("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
	}

	sbom, err := ds.database.GetSBOM(id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "SBOM not found"})
	}

	return c.JSON(sbom)
}

func (ds *SBOMService) HandleAPIComponents(c *fiber.Ctx) error {
	idParam := c.Params("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
	}

	components, err := ds.database.GetComponentsBySBOM(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get components"})
	}

	// Add vulnerability count for each component
	type ComponentWithVulnCount struct {
		*models.Component
		VulnerabilityCount int `json:"vulnerability_count"`
	}

	var enhancedComponents []ComponentWithVulnCount
	for _, component := range components {
		vulns, err := ds.database.GetVulnerabilitiesByComponent(component.ID)
		vulnCount := 0
		if err == nil {
			vulnCount = len(vulns)
		}

		enhancedComponents = append(enhancedComponents, ComponentWithVulnCount{
			Component:          component,
			VulnerabilityCount: vulnCount,
		})
	}

	return c.JSON(enhancedComponents)
}

// SBOM download handler
func (ds *SBOMService) HandleAPISBOMDownload(c *fiber.Ctx) error {
	idParam := c.Params("id")
	sbomID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
	}

	// Get SBOM from database
	sbom, err := ds.database.GetSBOM(sbomID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "SBOM not found"})
	}

	// Set headers for file download
	c.Set("Content-Type", "application/json")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=sbom-%d.json", sbomID))

	// Return raw SBOM data
	return c.SendString(sbom.RawSBOM)
}

// Component detail handler
func (ds *SBOMService) HandleAPIComponentDetail(c *fiber.Ctx) error {
	idParam := c.Params("id")
	componentID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid component ID"})
	}

	// Get component from database
	component, err := ds.database.GetComponent(componentID)
	if err != nil {
		if err.Error() == "component not found" {
			return c.Status(404).JSON(fiber.Map{"error": "Component not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get component"})
	}

	// Return component with proper field names
	response := map[string]any{
		"id":         component.ID,
		"name":       component.Name,
		"version":    component.Version,
		"type":       component.Type,
		"language":   component.Language,
		"purl":       component.PURL,
		"cpe":        component.CPE,
		"licenses":   component.Licenses,
		"locations":  component.Locations,
		"metadata":   component.Metadata,
		"created_at": component.CreatedAt,
		"updated_at": component.UpdatedAt,
	}

	return c.JSON(response)
}

func (ds *SBOMService) HandleAPILicensesBySBOM(c *fiber.Ctx) error {
	idParam := c.Params("id")
	sbomID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
	}

	// Get pagination parameters
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("pageSize", 20)
	if pageSize > 100 {
		pageSize = 100 // Limit max page size
	}
	if page < 1 {
		page = 1
	}

	offset := (page - 1) * pageSize

	// Get components for this SBOM
	components, err := ds.database.GetComponentsBySBOM(sbomID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get components"})
	}

	// Group components by license
	licenseGroups := make(map[string][]*models.Component)
	totalComponents := 0

	for _, component := range components {
		if len(component.Licenses) == 0 {
			// No license information
			licenseGroups["Unknown"] = append(licenseGroups["Unknown"], component)
		} else {
			// Component can have multiple licenses
			for _, license := range component.Licenses {
				if license == "" || license == "null" || license == "NOASSERTION" || license == "UNKNOWN" {
					licenseGroups["Unknown"] = append(licenseGroups["Unknown"], component)
				} else {
					licenseGroups[license] = append(licenseGroups[license], component)
				}
			}
		}
		totalComponents++
	}

	// Convert map to slice for pagination
	type LicenseGroup struct {
		License    string              `json:"license"`
		Components []*models.Component `json:"components"`
		Count      int                 `json:"count"`
	}

	var allGroups []LicenseGroup
	for license, comps := range licenseGroups {
		allGroups = append(allGroups, LicenseGroup{
			License:    license,
			Components: comps,
			Count:      len(comps),
		})
	}

	// Sort groups by license name
	sort.Slice(allGroups, func(i, j int) bool {
		// Put "Unknown" at the end
		if allGroups[i].License == "Unknown" {
			return false
		}
		if allGroups[j].License == "Unknown" {
			return true
		}
		return allGroups[i].License < allGroups[j].License
	})

	// Apply pagination
	totalGroups := len(allGroups)
	totalPages := (totalGroups + pageSize - 1) / pageSize

	start := offset
	end := offset + pageSize
	if start >= totalGroups {
		start = totalGroups
	}
	if end > totalGroups {
		end = totalGroups
	}

	paginatedGroups := make([]LicenseGroup, 0)
	if start < end {
		paginatedGroups = allGroups[start:end]
	}

	return c.JSON(fiber.Map{
		"license_groups":   paginatedGroups,
		"total_groups":     totalGroups,
		"total_components": totalComponents,
		"page":             page,
		"page_size":        pageSize,
		"total_pages":      totalPages,
		"has_next":         page < totalPages,
		"has_prev":         page > 1,
	})
}

// Delete API handlers

// handleAPIDeleteSBOM handles single SBOM deletion
func (ds *SBOMService) HandleAPIDeleteSBOM(c *fiber.Ctx) error {
	idParam := c.Params("id")
	sbomID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
	}

	// Check if SBOM exists
	sbom, err := ds.database.GetSBOM(sbomID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "SBOM not found"})
	}

	// Delete SBOM
	if err := ds.database.DeleteSBOM(sbomID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete SBOM"})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": fmt.Sprintf("SBOM '%s/%s' deleted successfully", sbom.RepoName, sbom.ModulePath),
	})
}

// handleAPIDeleteSBOMs handles multiple SBOM deletion
func (ds *SBOMService) HandleAPIDeleteSBOMs(c *fiber.Ctx) error {
	type DeleteSBOMsRequest struct {
		SBOMIDs []int `json:"sbom_ids"`
	}

	var req DeleteSBOMsRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if len(req.SBOMIDs) == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "No SBOM IDs provided"})
	}

	// Get SBOM info for response message
	var sbomInfos []map[string]string
	for _, id := range req.SBOMIDs {
		sbom, err := ds.database.GetSBOM(id)
		if err != nil {
			// Skip if SBOM doesn't exist
			continue
		}
		sbomInfos = append(sbomInfos, map[string]string{
			"repo_name":   sbom.RepoName,
			"module_path": sbom.ModulePath,
		})
	}

	// Delete SBOMs
	if err := ds.database.DeleteSBOMs(req.SBOMIDs); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete SBOMs"})
	}

	return c.JSON(fiber.Map{
		"success":       true,
		"message":       fmt.Sprintf("%d SBOM(s) deleted successfully", len(req.SBOMIDs)),
		"deleted_count": len(req.SBOMIDs),
		"deleted_sboms": sbomInfos,
	})
}

// handleAPIDeleteRepository handles repository deletion
func (ds *SBOMService) HandleAPIDeleteRepository(c *fiber.Ctx) error {
	repoName := c.Params("name")
	if repoName == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Repository name is required"})
	}

	// Get SBOMs for this repository for response message
	sboms, err := ds.database.GetSBOMsByRepository(repoName)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get repository SBOMs"})
	}

	if len(sboms) == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "Repository not found or no SBOMs exist"})
	}

	// Delete repository
	if err := ds.database.DeleteRepository(repoName); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete repository"})
	}

	// Build response with deleted modules info
	var modules []string
	for _, sbom := range sboms {
		modules = append(modules, sbom.ModulePath)
	}

	return c.JSON(fiber.Map{
		"success":       true,
		"message":       fmt.Sprintf("Repository '%s' and all %d SBOM(s) deleted successfully", repoName, len(sboms)),
		"deleted_count": len(sboms),
		"modules":       modules,
	})
}
