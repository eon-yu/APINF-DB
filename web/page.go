package web

import (
	"fmt"
	"oss-compliance-scanner/models"
	"oss-compliance-scanner/web/service"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
)

func (ds *AppServer) handleVulnerabilities(c *fiber.Ctx) error {
	// Get all vulnerabilities directly from the database
	allVulns, err := ds.database.GetAllVulnerabilities(1000)
	if err != nil {
		return c.Status(500).SendString("Failed to load vulnerabilities")
	}

	return c.Render("vulnerabilities", fiber.Map{
		"Title":           "Vulnerabilities",
		"Vulnerabilities": allVulns,
	})
}

func (ds *AppServer) handlePolicies(c *fiber.Ctx) error {
	licensePolicies, err := ds.database.GetActiveLicensePolicies()
	if err != nil {
		licensePolicies = []*models.LicensePolicy{}
	}

	vulnPolicies, err := ds.database.GetActiveVulnerabilityPolicies()
	if err != nil {
		vulnPolicies = []*models.VulnerabilityPolicy{}
	}

	return c.Render("policies", fiber.Map{
		"Title":                 "Policy Management",
		"LicensePolicies":       licensePolicies,
		"VulnerabilityPolicies": vulnPolicies,
	})
}

func (ds *AppServer) handleViolations(c *fiber.Ctx) error {
	// This would require additional DB queries for violations
	// For now, return empty data
	return c.Render("violations", fiber.Map{
		"Title": "Policy Violations",
	})
}
func (ds *AppServer) HandleDashboard(c *fiber.Ctx) error {
	stats, err := service.GetStats(ds.database)
	if err != nil {
		return c.Status(500).SendString("Failed to load dashboard stats")
	}

	return c.Render("dashboard", fiber.Map{
		"Title": "OSS Compliance Dashboard",
		"Stats": stats,
	})
}

// Admin page handler
func (ds *AppServer) handleAdmin(c *fiber.Ctx) error {
	return c.Render("admin", fiber.Map{
		"Title": "Admin Settings",
	})
}
func (ds *AppServer) handleReports(c *fiber.Ctx) error {
	scanResults, err := ds.database.GetLatestScanResults(20)
	if err != nil {
		return c.Status(500).SendString("Failed to load reports")
	}

	return c.Render("reports", fiber.Map{
		"Title":       "Scan Reports",
		"ScanResults": scanResults,
	})
}
func (ds *AppServer) HandleSBOMs(c *fiber.Ctx) error {
	// Get SBOMs directly from the sboms table
	sboms, err := ds.database.GetAllSBOMs(100)
	if err != nil {
		return c.Status(500).SendString("Failed to load SBOMs")
	}

	// Group SBOMs by repository
	repositoryGroups := make(map[string]*RepositoryInfo)

	for _, sbom := range sboms {
		if _, exists := repositoryGroups[sbom.RepoName]; !exists {
			repositoryGroups[sbom.RepoName] = &RepositoryInfo{
				Name:                 sbom.RepoName,
				Modules:              []*models.SBOM{},
				UniqueModules:        []ModuleInfo{},
				ModuleCount:          0,
				TotalComponents:      0,
				TotalVulnerabilities: 0,
				LastScanDate:         sbom.ScanDate.Format("2006-01-02 15:04"),
				RiskLevel:            "low",
			}
		}

		repo := repositoryGroups[sbom.RepoName]
		repo.Modules = append(repo.Modules, sbom)

		// Update last scan date if this SBOM is more recent
		lastScanTime, err := time.Parse("2006-01-02 15:04", repo.LastScanDate)
		if err == nil && sbom.ScanDate.After(lastScanTime) {
			repo.LastScanDate = sbom.ScanDate.Format("2006-01-02 15:04")
		}
	}

	// Process unique modules for each repository
	for _, repo := range repositoryGroups {
		moduleMap := make(map[string]*ModuleInfo)

		// Group SBOMs by module path to find unique modules
		for _, sbom := range repo.Modules {
			if moduleInfo, exists := moduleMap[sbom.ModulePath]; !exists {
				moduleMap[sbom.ModulePath] = &ModuleInfo{
					ModulePath:     sbom.ModulePath,
					LatestSBOM:     sbom,
					ComponentCount: sbom.ComponentCount,
					VulnCount:      0,
					AllSBOMs:       []*models.SBOM{sbom},
				}
			} else {
				// Add to all SBOMs list
				moduleInfo.AllSBOMs = append(moduleInfo.AllSBOMs, sbom)
				// Update latest SBOM if this one is more recent
				if sbom.ScanDate.After(moduleInfo.LatestSBOM.ScanDate) {
					moduleInfo.LatestSBOM = sbom
					moduleInfo.ComponentCount = sbom.ComponentCount
				}
			}
		}

		// Convert map to slice and calculate totals from latest SBOMs only
		repo.UniqueModules = make([]ModuleInfo, 0, len(moduleMap))
		repo.TotalComponents = 0

		for _, moduleInfo := range moduleMap {
			repo.UniqueModules = append(repo.UniqueModules, *moduleInfo)
			repo.TotalComponents += moduleInfo.ComponentCount
		}

		repo.ModuleCount = len(moduleMap)
	}

	// Calculate vulnerability counts and risk levels for each repository
	for _, repo := range repositoryGroups {
		criticalCount, highCount := 0, 0

		// Only count vulnerabilities from latest SBOMs of unique modules
		for i := range repo.UniqueModules {
			moduleInfo := &repo.UniqueModules[i]
			// Get vulnerabilities for this module's latest SBOM
			vulns, err := ds.database.GetVulnerabilitiesBySBOM(moduleInfo.LatestSBOM.ID)
			if err == nil {
				moduleInfo.VulnCount = len(vulns)
				repo.TotalVulnerabilities += len(vulns)

				for _, vuln := range vulns {
					switch vuln.Severity {
					case "Critical":
						criticalCount++
					case "High":
						highCount++
					}
				}
			}
		}

		// Determine risk level
		if criticalCount > 0 {
			repo.RiskLevel = "critical"
		} else if highCount > 5 {
			repo.RiskLevel = "high"
		} else if highCount > 0 {
			repo.RiskLevel = "medium"
		} else {
			repo.RiskLevel = "low"
		}
	}

	return c.Render("sboms", fiber.Map{
		"Title":            "Repository Management",
		"SBOMs":            sboms, // For flat view
		"RepositoryGroups": repositoryGroups,
	})
}

func (ds *AppServer) HandleSBOMDetail(c *fiber.Ctx) error {
	idParam := c.Params("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).SendString("Invalid SBOM ID")
	}

	sbom, err := ds.database.GetSBOM(id)
	if err != nil {
		return c.Status(404).SendString("SBOM not found")
	}

	components, err := ds.database.GetComponentsBySBOM(id)
	if err != nil {
		components = []*models.Component{} // Empty list on error
	}

	return c.Render("sbom_detail", fiber.Map{
		"Title":      fmt.Sprintf("SBOM Details - %s", sbom.RepoName),
		"SBOM":       sbom,
		"Components": components,
	})
}
