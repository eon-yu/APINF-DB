package service

import (
	"fmt"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"sort"

	"github.com/gofiber/fiber/v2"
)

type DashboardService struct {
	database *db.Database
}

func NewDashboardService(db *db.Database) *DashboardService {
	return &DashboardService{database: db}
}

func GetStats(database *db.Database) (map[string]any, error) {
	// Get SBOMs for stats
	allSBOMs, err := database.GetAllSBOMs(100)
	if err != nil {
		fmt.Printf("Error getting SBOMs: %v\n", err)
		return nil, err
	}
	fmt.Printf("Found %d SBOMs\n", len(allSBOMs))

	// Filter to get only latest SBOM per repository
	latestSBOMs := make(map[string]*models.SBOM)
	for _, sbom := range allSBOMs {
		repoKey := sbom.RepoName + "|" + sbom.ModulePath
		if existing, exists := latestSBOMs[repoKey]; !exists || sbom.ScanDate.After(existing.ScanDate) {
			latestSBOMs[repoKey] = sbom
		}
	}

	// Convert map to slice for easier processing
	var sboms []*models.SBOM
	for _, sbom := range latestSBOMs {
		sboms = append(sboms, sbom)
	}

	// Get scan results for additional stats
	scanResults, err := database.GetLatestScanResults(100)
	if err != nil {
		scanResults = []*models.ScanResult{} // Empty slice on error
	}

	stats := map[string]any{
		"total_sboms":           len(allSBOMs), // Total SBOMs ever created
		"unique_repositories":   len(sboms),    // Unique repositories
		"total_scans":           len(scanResults),
		"total_components":      0,
		"total_vulnerabilities": 0,
		"critical_vulns":        0,
		"high_vulns":            0,
		"medium_vulns":          0,
		"low_vulns":             0,
		"repositories":          make(map[string]bool),
		"last_scan":             nil,
	}
	fmt.Printf("Stats: %+v\n", stats)

	// Track repositories for counting (done in the vulnerability calculation loop above)
	for _, sbom := range sboms {
		repos := stats["repositories"].(map[string]bool)
		repos[sbom.RepoName] = true
	}

	if len(scanResults) > 0 {
		stats["last_scan"] = scanResults[0].ScanStartTime
	}

	// Calculate totals from latest SBOMs only (one per repository)
	var totalComponents int
	var totalVulnerabilities int
	var criticalVulns, highVulns, mediumVulns, lowVulns int

	// Use the filtered sboms which already contain only latest per repository
	for _, sbom := range sboms {
		// Add component count
		totalComponents += sbom.ComponentCount

		// Count vulnerabilities for this SBOM
		components, err := database.GetComponentsBySBOM(sbom.ID)
		if err != nil {
			continue
		}

		for _, component := range components {
			vulns, err := database.GetVulnerabilitiesByComponent(component.ID)
			if err != nil {
				continue
			}

			totalVulnerabilities += len(vulns)

			// Count by severity
			for _, vuln := range vulns {
				switch vuln.Severity {
				case "Critical":
					criticalVulns++
				case "High":
					highVulns++
				case "Medium":
					mediumVulns++
				case "Low":
					lowVulns++
				}
			}
		}
	}

	// Update stats with calculated values
	stats["total_components"] = totalComponents
	stats["total_vulnerabilities"] = totalVulnerabilities
	stats["critical_vulns"] = criticalVulns
	stats["high_vulns"] = highVulns
	stats["medium_vulns"] = mediumVulns
	stats["low_vulns"] = lowVulns

	stats["total_repositories"] = len(stats["repositories"].(map[string]bool))

	// Convert repositories map to detailed repository info for recent repositories display
	type RepoInfo struct {
		RepoName       string `json:"repo_name"`
		SBOMID         int    `json:"sbom_id"`
		ComponentCount int    `json:"component_count"`
		VulnCount      int    `json:"vuln_count"`
		ScanDate       string `json:"scan_date"`
	}

	var recentRepoInfo []RepoInfo
	for _, sbom := range sboms {
		// Count vulnerabilities for this SBOM
		components, err := database.GetComponentsBySBOM(sbom.ID)
		vulnCount := 0
		if err == nil {
			for _, component := range components {
				vulns, err := database.GetVulnerabilitiesByComponent(component.ID)
				if err == nil {
					vulnCount += len(vulns)
				}
			}
		}

		repoInfo := RepoInfo{
			RepoName:       sbom.RepoName,
			SBOMID:         sbom.ID,
			ComponentCount: sbom.ComponentCount,
			VulnCount:      vulnCount,
			ScanDate:       sbom.ScanDate.Format("2006-01-02 15:04"),
		}
		recentRepoInfo = append(recentRepoInfo, repoInfo)
	}

	// Sort by repository name for consistent display
	sort.Slice(recentRepoInfo, func(i, j int) bool {
		return recentRepoInfo[i].RepoName < recentRepoInfo[j].RepoName
	})

	stats["recent_repository_info"] = recentRepoInfo
	delete(stats, "repositories") // Remove the map, keep only count

	return stats, nil
}

func (ds *DashboardService) HandleStats(c *fiber.Ctx) error {
	stats, err := GetStats(ds.database)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get stats"})
	}
	return c.JSON(stats)
}
