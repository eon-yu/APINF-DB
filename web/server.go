package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"oss-compliance-scanner/notifier"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
)

// DashboardServer represents the web dashboard server
type DashboardServer struct {
	app      *fiber.App
	database *db.Database
	port     string
}

// RepositoryInfo holds information about a repository and its modules
type RepositoryInfo struct {
	Name                 string         `json:"name"`
	Modules              []*models.SBOM `json:"modules"`          // All SBOM executions
	UniqueModules        []ModuleInfo   `json:"unique_modules"`   // Unique modules with latest info
	ModuleCount          int            `json:"module_count"`     // Count of unique modules
	TotalComponents      int            `json:"total_components"` // From latest SBOMs only
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	LastScanDate         string         `json:"last_scan_date"`
	RiskLevel            string         `json:"risk_level"`
}

// ModuleInfo represents information about a unique module
type ModuleInfo struct {
	ModulePath     string         `json:"module_path"`
	LatestSBOM     *models.SBOM   `json:"latest_sbom"`
	ComponentCount int            `json:"component_count"`
	VulnCount      int            `json:"vuln_count"`
	AllSBOMs       []*models.SBOM `json:"all_sboms"` // All SBOM executions for this module
}

// NewDashboardServer creates a new dashboard server instance
func NewDashboardServer(database *db.Database, port string) *DashboardServer {
	// HTML template engine
	engine := html.New("./web/templates", ".html")
	engine.Reload(true) // Optional. Default: false
	engine.Debug(true)  // Optional. Default: false

	// Fiber app with template engine
	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layouts/main",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New())

	server := &DashboardServer{
		app:      app,
		database: database,
		port:     port,
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures all web routes
func (ds *DashboardServer) setupRoutes() {
	// Static files
	ds.app.Static("/static", "./web/static")

	// Web pages
	ds.app.Get("/", ds.handleDashboard)
	ds.app.Get("/sboms", ds.handleSBOMs)
	ds.app.Get("/sboms/:id", ds.handleSBOMDetail)
	ds.app.Get("/vulnerabilities", ds.handleVulnerabilities)
	ds.app.Get("/policies", ds.handlePolicies)
	ds.app.Get("/violations", ds.handleViolations)
	ds.app.Get("/reports", ds.handleReports)
	ds.app.Get("/admin", ds.handleAdmin)

	// API endpoints
	api := ds.app.Group("/api/v1")
	api.Get("/health", ds.handleHealthCheck)
	api.Get("/stats", ds.handleStats)
	api.Get("/sboms", ds.handleAPISBOMs)
	api.Get("/sboms/:id", ds.handleAPISBOMDetail)
	api.Get("/sboms/:id/components", ds.handleAPIComponents)
	api.Get("/sboms/:id/vulnerabilities", ds.handleAPIVulnerabilities)
	api.Get("/vulnerabilities", ds.handleAPIVulnerabilities)
	api.Get("/violations", ds.handleAPIViolations)
	api.Get("/scan-results", ds.handleAPIScanResults)

	// Policy management API
	api.Get("/policies/licenses", ds.handleAPILicensePolicies)
	api.Get("/policies/vulnerabilities", ds.handleAPIVulnerabilityPolicies)
	api.Post("/policies/licenses", ds.handleAPICreateLicensePolicy)
	api.Post("/policies/vulnerabilities", ds.handleAPICreateVulnerabilityPolicy)
	api.Delete("/policies/licenses/:id", ds.handleAPIDeleteLicensePolicy)
	api.Delete("/policies/vulnerabilities/:id", ds.handleAPIDeleteVulnerabilityPolicy)

	// Violation management API
	api.Put("/violations/:id/resolve", ds.handleAPIResolveViolation)
	api.Put("/violations/:id/ignore", ds.handleAPIIgnoreViolation)

	// Settings API
	api.Get("/settings", ds.handleAPIGetSettings)
	api.Put("/settings", ds.handleAPIPutSettings)

	// Scan API
	api.Post("/scan/start", ds.handleAPIStartScan)
	api.Get("/scan/status/:id", ds.handleAPIScanStatus)
	api.Post("/sboms/:id/rescan", ds.handleAPIRescanSBOM)
	api.Post("/repositories/:name/rescan", ds.handleAPIRescanRepository)
	api.Get("/sboms/:id/download", ds.handleAPISBOMDownload)
	api.Get("/components/:id", ds.handleAPIComponentDetail)
	api.Get("/sboms/:id/licenses", ds.handleAPILicensesBySBOM)

	// Delete API
	api.Delete("/sboms/:id", ds.handleAPIDeleteSBOM)
	api.Delete("/sboms", ds.handleAPIDeleteSBOMs)
	api.Delete("/repositories/:name", ds.handleAPIDeleteRepository)

	// Health check API
	api.Get("/health/db", ds.handleAPIHealthDB)
	api.Get("/health/scanner", ds.handleAPIHealthScanner)
	api.Get("/health/notifier", ds.handleAPIHealthNotifier)

	// Notification test API
	api.Post("/notifications/slack/test", ds.handleAPISlackTest)

	// Report generation API
	api.Get("/reports", ds.handleAPIReports)
	api.Post("/reports", ds.handleAPICreateReport)
	api.Get("/reports/:id", ds.handleAPIReportDetail)
	api.Get("/reports/:id/download", ds.handleAPIReportDownload)
	api.Delete("/reports/:id", ds.handleAPIDeleteReport)
}

// Start starts the web server
func (ds *DashboardServer) Start() error {
	fmt.Printf("🌐 Starting OSS Compliance Dashboard on port %s\n", ds.port)
	return ds.app.Listen(":" + ds.port)
}

// Stop gracefully stops the web server
func (ds *DashboardServer) Stop() error {
	return ds.app.Shutdown()
}

// Test sends a test request to the server (for testing purposes)
func (ds *DashboardServer) Test(req *http.Request) (*http.Response, error) {
	return ds.app.Test(req)
}

// Web page handlers

func (ds *DashboardServer) handleDashboard(c *fiber.Ctx) error {
	stats, err := ds.getStats()
	if err != nil {
		return c.Status(500).SendString("Failed to load dashboard stats")
	}

	return c.Render("dashboard", fiber.Map{
		"Title": "OSS Compliance Dashboard",
		"Stats": stats,
	})
}

func (ds *DashboardServer) handleSBOMs(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleSBOMDetail(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleVulnerabilities(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handlePolicies(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleViolations(c *fiber.Ctx) error {
	// This would require additional DB queries for violations
	// For now, return empty data
	return c.Render("violations", fiber.Map{
		"Title": "Policy Violations",
	})
}

func (ds *DashboardServer) handleReports(c *fiber.Ctx) error {
	scanResults, err := ds.database.GetLatestScanResults(20)
	if err != nil {
		return c.Status(500).SendString("Failed to load reports")
	}

	return c.Render("reports", fiber.Map{
		"Title":       "Scan Reports",
		"ScanResults": scanResults,
	})
}

// API handlers

func (ds *DashboardServer) handleHealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

func (ds *DashboardServer) handleStats(c *fiber.Ctx) error {
	stats, err := ds.getStats()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get stats"})
	}
	return c.JSON(stats)
}

func (ds *DashboardServer) handleAPISBOMs(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 50)
	sboms, err := ds.database.GetAllSBOMs(limit)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get SBOMs"})
	}
	return c.JSON(sboms)
}

func (ds *DashboardServer) handleAPISBOMDetail(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleAPIComponents(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleAPIVulnerabilities(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleAPIViolations(c *fiber.Ctx) error {
	// This would require violation tracking in the database
	return c.JSON([]interface{}{})
}

func (ds *DashboardServer) handleAPIScanResults(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 20)
	results, err := ds.database.GetLatestScanResults(limit)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get scan results"})
	}
	return c.JSON(results)
}

func (ds *DashboardServer) handleAPILicensePolicies(c *fiber.Ctx) error {
	policies, err := ds.database.GetActiveLicensePolicies()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get license policies"})
	}
	return c.JSON(policies)
}

func (ds *DashboardServer) handleAPIVulnerabilityPolicies(c *fiber.Ctx) error {
	policies, err := ds.database.GetActiveVulnerabilityPolicies()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get vulnerability policies"})
	}
	return c.JSON(policies)
}

func (ds *DashboardServer) handleAPICreateLicensePolicy(c *fiber.Ctx) error {
	var policy models.LicensePolicy
	if err := json.Unmarshal(c.Body(), &policy); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if err := ds.database.CreateLicensePolicy(&policy); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create policy"})
	}

	return c.Status(201).JSON(policy)
}

func (ds *DashboardServer) handleAPICreateVulnerabilityPolicy(c *fiber.Ctx) error {
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

func (ds *DashboardServer) getStats() (map[string]interface{}, error) {
	// Get SBOMs for stats
	allSBOMs, err := ds.database.GetAllSBOMs(100)
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
	scanResults, err := ds.database.GetLatestScanResults(100)
	if err != nil {
		scanResults = []*models.ScanResult{} // Empty slice on error
	}

	stats := map[string]interface{}{
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
		components, err := ds.database.GetComponentsBySBOM(sbom.ID)
		if err != nil {
			continue
		}

		for _, component := range components {
			vulns, err := ds.database.GetVulnerabilitiesByComponent(component.ID)
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
		components, err := ds.database.GetComponentsBySBOM(sbom.ID)
		vulnCount := 0
		if err == nil {
			for _, component := range components {
				vulns, err := ds.database.GetVulnerabilitiesByComponent(component.ID)
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

// Admin page handler
func (ds *DashboardServer) handleAdmin(c *fiber.Ctx) error {
	return c.Render("admin", fiber.Map{
		"Title": "Admin Settings",
	})
}

// Policy management handlers
func (ds *DashboardServer) handleAPIDeleteLicensePolicy(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleAPIDeleteVulnerabilityPolicy(c *fiber.Ctx) error {
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

// Violation management handlers
func (ds *DashboardServer) handleAPIResolveViolation(c *fiber.Ctx) error {
	idParam := c.Params("id")
	_, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid violation ID"})
	}

	// This would require violation tracking in the database
	// For now, return success
	return c.JSON(fiber.Map{"status": "resolved"})
}

func (ds *DashboardServer) handleAPIIgnoreViolation(c *fiber.Ctx) error {
	idParam := c.Params("id")
	_, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid violation ID"})
	}

	// This would require violation tracking in the database
	// For now, return success
	return c.JSON(fiber.Map{"status": "ignored"})
}

// Settings handlers
func (ds *DashboardServer) handleAPIGetSettings(c *fiber.Ctx) error {
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

func (ds *DashboardServer) handleAPIPutSettings(c *fiber.Ctx) error {
	var settings map[string]interface{}
	if err := json.Unmarshal(c.Body(), &settings); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid settings format"})
	}

	// In a real implementation, you would save these settings to a database or config file
	// For now, just return success
	return c.JSON(fiber.Map{"status": "settings updated"})
}

// Health check handlers
func (ds *DashboardServer) handleAPIHealthDB(c *fiber.Ctx) error {
	// Check database connectivity
	if err := ds.database.Ping(); err != nil {
		return c.Status(503).JSON(fiber.Map{"status": "error", "message": "Database connection failed"})
	}
	return c.JSON(fiber.Map{"status": "ok", "message": "Database is healthy"})
}

func (ds *DashboardServer) handleAPIHealthScanner(c *fiber.Ctx) error {
	// Check if scanner tools are available
	// For now, return healthy
	return c.JSON(fiber.Map{"status": "ok", "message": "Scanner tools are available"})
}

func (ds *DashboardServer) handleAPIHealthNotifier(c *fiber.Ctx) error {
	// Check notification service health
	// For now, return healthy
	return c.JSON(fiber.Map{"status": "ok", "message": "Notification service is healthy"})
}

// Scan management handlers
func (ds *DashboardServer) handleAPIStartScan(c *fiber.Ctx) error {
	type ScanRequest struct {
		RepoPath   string `json:"repo_path"`
		RepoName   string `json:"repo_name"`
		ModulePath string `json:"module_path"`
		ScanType   string `json:"scan_type"`
	}

	var req ScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate required fields
	if req.RepoPath == "" || req.RepoName == "" {
		return c.Status(400).JSON(fiber.Map{"error": "repo_path and repo_name are required"})
	}

	// For now, simulate scan initiation
	scanID := fmt.Sprintf("scan_%d", time.Now().Unix())

	// In a real implementation, you would:
	// 1. Create a scan job in the database
	// 2. Queue the scan for background processing
	// 3. Return the scan ID for status tracking

	// Start background scan process
	go func() {
		ds.executeScan(scanID, req.RepoPath, req.RepoName, req.ModulePath, req.ScanType)
	}()

	return c.JSON(fiber.Map{
		"scan_id": scanID,
		"status":  "started",
		"message": "스캔이 시작되었습니다.",
	})
}

func (ds *DashboardServer) handleAPIScanStatus(c *fiber.Ctx) error {
	scanID := c.Params("id")
	if scanID == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Scan ID is required"})
	}

	// In a real implementation, you would:
	// 1. Query the database for scan status
	// 2. Return actual progress information

	// For now, simulate scan progress
	return c.JSON(fiber.Map{
		"scan_id":  scanID,
		"status":   "in_progress",
		"message":  "스캔 진행 중...",
		"details":  "의존성 분석 중입니다.",
		"progress": 45,
	})
}

func (ds *DashboardServer) handleAPIRescanSBOM(c *fiber.Ctx) error {
	idParam := c.Params("id")
	sbomID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
	}

	// Get existing SBOM details
	sbom, err := ds.database.GetSBOM(sbomID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "SBOM not found"})
	}

	// Create new scan ID
	scanID := fmt.Sprintf("rescan_%d_%d", sbomID, time.Now().Unix())

	// Start background rescan process
	go func() {
		// Note: RepoPath is not stored in SBOM model, using empty string for now
		// In production, this should be stored separately or added to SBOM model
		ds.executeScan(scanID, "", sbom.RepoName, sbom.ModulePath, "both")
	}()

	return c.JSON(fiber.Map{
		"scan_id": scanID,
		"status":  "started",
		"message": "재스캔이 시작되었습니다.",
	})
}

// Repository rescan handler - handles single module vs multi-module scenarios
func (ds *DashboardServer) handleAPIRescanRepository(c *fiber.Ctx) error {
	repoName := c.Params("name")
	if repoName == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Repository name is required"})
	}

	// Get all SBOMs for this repository
	allSBOMs, err := ds.database.GetAllSBOMs(1000) // Get enough to find all for this repo
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get SBOMs"})
	}

	// Filter SBOMs for this repository and find latest per module
	moduleMap := make(map[string]*models.SBOM)
	for _, sbom := range allSBOMs {
		if sbom.RepoName != repoName {
			continue
		}

		if existing, exists := moduleMap[sbom.ModulePath]; !exists || sbom.ScanDate.After(existing.ScanDate) {
			moduleMap[sbom.ModulePath] = sbom
		}
	}

	if len(moduleMap) == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "No SBOMs found for repository"})
	}

	// Determine scan strategy
	moduleCount := len(moduleMap)
	isSingleModule := moduleCount == 1

	var scanIDs []string

	// Create scan IDs and start scans for each unique module's latest SBOM
	for modulePath, sbom := range moduleMap {
		scanID := fmt.Sprintf("repo_rescan_%s_%s_%d", repoName, modulePath, time.Now().Unix())
		scanIDs = append(scanIDs, scanID)

		// Start background rescan process for this module
		go func(id, repo, module string) {
			ds.executeScan(id, "", repo, module, "both")
		}(scanID, sbom.RepoName, sbom.ModulePath)
	}

	// Create response message based on module count
	var message string
	if isSingleModule {
		message = fmt.Sprintf("\"%s\" 저장소의 모듈 재스캔이 시작되었습니다.", repoName)
	} else {
		message = fmt.Sprintf("\"%s\" 저장소의 %d개 모듈 재스캔이 시작되었습니다.", repoName, moduleCount)
	}

	return c.JSON(fiber.Map{
		"scan_ids":     scanIDs,
		"module_count": moduleCount,
		"is_single":    isSingleModule,
		"status":       "started",
		"message":      message,
		"modules":      getModulePathsFromMap(moduleMap),
	})
}

// Helper function to extract module paths from map
func getModulePathsFromMap(moduleMap map[string]*models.SBOM) []string {
	var paths []string
	for path := range moduleMap {
		paths = append(paths, path)
	}
	return paths
}

// executeScan simulates the actual scan execution
func (ds *DashboardServer) executeScan(scanID, repoPath, repoName, modulePath, scanType string) {
	// This is a simplified simulation of the scan process
	// In a real implementation, this would:
	// 1. Run syft to generate SBOM
	// 2. Run grype to find vulnerabilities
	// 3. Store results in the database
	// 4. Update scan status

	fmt.Printf("Starting scan %s for repository %s at %s\n", scanID, repoName, repoPath)

	// Simulate scan duration
	time.Sleep(10 * time.Second)

	fmt.Printf("Scan %s completed successfully\n", scanID)
}

// SBOM download handler
func (ds *DashboardServer) handleAPISBOMDownload(c *fiber.Ctx) error {
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
func (ds *DashboardServer) handleAPIComponentDetail(c *fiber.Ctx) error {
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
	response := map[string]interface{}{
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

func (ds *DashboardServer) handleAPILicensesBySBOM(c *fiber.Ctx) error {
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

// Slack test request structure
type SlackTestRequest struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
}

// handleAPISlackTest sends a test Slack notification
func (ds *DashboardServer) handleAPISlackTest(c *fiber.Ctx) error {
	var req SlackTestRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.WebhookURL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "webhook_url is required"})
	}

	// Create Slack notifier with test configuration
	slackNotifier := notifier.NewSlackNotifier(
		req.WebhookURL,
		"OSS Compliance Scanner",
		req.Channel,
		":shield:",
	)

	// Validate configuration first
	if err := slackNotifier.ValidateConfiguration(); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   "Invalid Slack configuration",
			"details": err.Error(),
		})
	}

	// Send a custom test message
	testMessage := fmt.Sprintf(`🧪 *OSS Compliance Scanner - 알림 테스트*

✅ Slack 알림 기능이 정상적으로 작동하고 있습니다.

*시스템 정보:* OSS Compliance Scanner v1.0.0
*테스트 시간:* %s
*참고사항:* 이 메시지는 관리자 페이지에서 발송된 테스트 알림입니다.`,
		time.Now().Format("2006-01-02 15:04:05"))

	if err := slackNotifier.SendCustomMessage(testMessage, req.Channel); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to send Slack test notification",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Slack 테스트 알림이 성공적으로 전송되었습니다.",
	})
}

// sendSlackMessage is a helper function to send Slack messages
func (ds *DashboardServer) sendSlackMessage(slackNotifier *notifier.SlackNotifier, message *notifier.SlackMessage) error {
	// Use the notifier's SendCustomMessage method for simple text
	if len(message.Attachments) == 0 {
		return slackNotifier.SendCustomMessage(message.Text, message.Channel)
	}

	// For messages with attachments, convert to text format
	messageText := message.Text
	if len(message.Attachments) > 0 {
		attachment := message.Attachments[0]
		if len(attachment.Fields) > 0 {
			messageText += "\n\n"
			for _, field := range attachment.Fields {
				messageText += fmt.Sprintf("*%s:* %s\n", field.Title, field.Value)
			}
		}
	}

	return slackNotifier.SendCustomMessage(messageText, message.Channel)
}

// Delete API handlers

// handleAPIDeleteSBOM handles single SBOM deletion
func (ds *DashboardServer) handleAPIDeleteSBOM(c *fiber.Ctx) error {
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
func (ds *DashboardServer) handleAPIDeleteSBOMs(c *fiber.Ctx) error {
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
func (ds *DashboardServer) handleAPIDeleteRepository(c *fiber.Ctx) error {
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

// Report API handlers

// handleAPIReports returns all reports
func (ds *DashboardServer) handleAPIReports(c *fiber.Ctx) error {
	reports, err := ds.database.GetAllReports(100)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch reports"})
	}

	return c.JSON(reports)
}

// handleAPICreateReport creates a new report
func (ds *DashboardServer) handleAPICreateReport(c *fiber.Ctx) error {
	var req models.ReportConfig
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate required fields
	if req.DateFrom == "" || req.DateTo == "" {
		return c.Status(400).JSON(fiber.Map{"error": "date_from and date_to are required"})
	}

	// Create report record
	report := &models.Report{
		Title:        fmt.Sprintf("Scan Report - %s to %s", req.DateFrom, req.DateTo),
		Type:         "pdf", // Default to PDF
		Status:       "generating",
		Format:       "summary", // Default format
		GeneratedBy:  "system",  // In production, get from user context
		CreatedAt:    time.Now(),
		ReportConfig: req,
		Metadata:     make(map[string]interface{}),
	}

	// Save report to database
	if err := ds.database.CreateReport(report); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create report"})
	}

	// Start background report generation
	go ds.generateReport(report.ID, req)

	return c.JSON(fiber.Map{
		"report_id": report.ID,
		"status":    "generating",
		"message":   "Report generation started",
	})
}

// handleAPIReportDetail returns details of a specific report
func (ds *DashboardServer) handleAPIReportDetail(c *fiber.Ctx) error {
	idParam := c.Params("id")
	reportID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid report ID"})
	}

	report, err := ds.database.GetReport(reportID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Report not found"})
	}

	return c.JSON(report)
}

// handleAPIReportDownload downloads a generated report
func (ds *DashboardServer) handleAPIReportDownload(c *fiber.Ctx) error {
	id := c.Params("id")
	reportID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid report ID",
		})
	}

	report, err := ds.database.GetReport(reportID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Report not found",
		})
	}

	if report.Status != "completed" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Report is not ready for download",
		})
	}

	// Get the actual content type based on file extension
	contentType := "application/octet-stream"
	if strings.HasSuffix(report.FilePath, ".pdf") {
		contentType = "application/pdf"
	} else if strings.HasSuffix(report.FilePath, ".csv") {
		contentType = "text/csv"
	} else if strings.HasSuffix(report.FilePath, ".xlsx") {
		contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}

	// Set appropriate headers
	c.Set("Content-Type", contentType)
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		filepath.Base(report.FilePath)))

	return c.SendFile(report.FilePath)
}

// handleAPIDeleteReport deletes a report
func (ds *DashboardServer) handleAPIDeleteReport(c *fiber.Ctx) error {
	idParam := c.Params("id")
	reportID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid report ID"})
	}

	// Get report to check if file exists
	report, err := ds.database.GetReport(reportID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Report not found"})
	}

	// Delete file if it exists
	if report.FilePath != "" {
		if _, err := os.Stat(report.FilePath); err == nil {
			os.Remove(report.FilePath)
		}
	}

	// Delete from database
	if err := ds.database.DeleteReport(reportID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete report"})
	}

	return c.Status(204).Send(nil)
}

// Helper functions for report generation

func (ds *DashboardServer) generateReport(reportID int, config models.ReportConfig) {
	log.Printf("보고서 생성 시작: ID=%d, Config=%+v", reportID, config)

	// Update status to generating
	if err := ds.database.UpdateReportStatus(reportID, "generating", "", 0); err != nil {
		log.Printf("보고서 상태 업데이트 실패 (generating): %v", err)
		return
	}

	// Get report data
	log.Printf("보고서 데이터 수집 중...")
	reportData, err := ds.database.GetReportData(config)
	if err != nil {
		log.Printf("보고서 데이터 수집 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	log.Printf("보고서 데이터 수집 완료: 저장소 %d개, SBOM %d개, 컴포넌트 %d개",
		reportData.Summary.TotalRepositories, reportData.Summary.TotalSBOMs, reportData.Summary.TotalComponents)

	// Create reports directory if it doesn't exist
	reportsDir := "./reports"
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		log.Printf("보고서 디렉토리 생성 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	// Generate file based on report type
	timestamp := time.Now().Format("20060102_150405")
	var filename, filePath string

	// Get the actual report type from the request, default to 'pdf'
	reportType := config.ReportType
	if reportType == "" {
		reportType = "pdf"
	}

	switch reportType {
	case "csv":
		filename = fmt.Sprintf("scan_report_%s_%d.csv", timestamp, reportID)
		filePath = filepath.Join(reportsDir, filename)
		err = ds.generateCSVReport(reportData, filePath)
	case "excel":
		filename = fmt.Sprintf("scan_report_%s_%d.xlsx", timestamp, reportID)
		filePath = filepath.Join(reportsDir, filename)
		err = ds.generateExcelReport(reportData, filePath)
	default: // pdf
		filename = fmt.Sprintf("scan_report_%s_%d.pdf", timestamp, reportID)
		filePath = filepath.Join(reportsDir, filename)
		err = ds.generatePDFReport(reportData, filePath)
	}

	if err != nil {
		log.Printf("보고서 파일 생성 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	// Get file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("보고서 파일 정보 확인 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	log.Printf("보고서 생성 완료: %s (크기: %d bytes)", filePath, fileInfo.Size())

	// Update status to completed
	if err := ds.database.UpdateReportStatus(reportID, "completed", filePath, fileInfo.Size()); err != nil {
		log.Printf("보고서 상태 업데이트 실패 (completed): %v", err)
		return
	}

	log.Printf("보고서 ID %d 생성 완료", reportID)
}

func (ds *DashboardServer) generatePDFReport(data *models.ReportData, filePath string) error {
	// Create a proper text-based report that can be read as a document
	content := ds.generateTextReport(data)

	// For now, we'll create a formatted text file with .pdf extension
	// In production, you would use a proper PDF library like gofpdf or wkhtmltopdf

	// Add proper document structure
	documentContent := fmt.Sprintf(`%%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length %d
>>
stream
BT
/F1 12 Tf
72 720 Td
(%s) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000136 00000 n 
0000000217 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
%d
%%%%EOF`, len(content), content, 300+len(content))

	return os.WriteFile(filePath, []byte(documentContent), 0644)
}

func (ds *DashboardServer) generateCSVReport(data *models.ReportData, filePath string) error {
	var csvContent strings.Builder

	// Add BOM for proper UTF-8 encoding in Excel
	csvContent.WriteString("\uFEFF")

	// Header
	csvContent.WriteString("Repository,Module Count,Components,Vulnerabilities,Critical,High,Medium,Low,Risk Level,Last Scan\n")

	// Data rows - show repository summary data
	for _, repo := range data.Repositories {
		csvContent.WriteString(fmt.Sprintf("%s,%d,%d,%d,%d,%d,%d,%d,%s,%s\n",
			escapeCsv(repo.RepoName),
			repo.ModuleCount,
			repo.TotalComponents,
			repo.TotalVulns,
			repo.VulnsBySeverity["critical"],
			repo.VulnsBySeverity["high"],
			repo.VulnsBySeverity["medium"],
			repo.VulnsBySeverity["low"],
			escapeCsv(repo.RiskLevel),
			repo.LastScanDate.Format("2006-01-02 15:04:05"),
		))
	}

	return os.WriteFile(filePath, []byte(csvContent.String()), 0644)
}

func (ds *DashboardServer) generateExcelReport(data *models.ReportData, filePath string) error {
	// For now, generate CSV format with .xlsx extension
	// In production, use a proper Excel library like excelize
	return ds.generateCSVReport(data, filePath)
}

// Helper function to escape CSV values
func escapeCsv(value string) string {
	if strings.Contains(value, ",") || strings.Contains(value, "\"") || strings.Contains(value, "\n") {
		value = strings.ReplaceAll(value, "\"", "\"\"")
		return "\"" + value + "\""
	}
	return value
}

func (ds *DashboardServer) generateTextReport(data *models.ReportData) string {
	var report strings.Builder

	report.WriteString("OSS COMPLIANCE SCAN REPORT\n")
	report.WriteString("=========================\n\n")
	report.WriteString(fmt.Sprintf("Generated: %s\n", data.GeneratedAt.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("Scan Period: %s\n", data.ScanPeriod))
	report.WriteString(fmt.Sprintf("Total Scans: %d\n\n", data.TotalScans))

	// Summary section
	report.WriteString("EXECUTIVE SUMMARY\n")
	report.WriteString("-----------------\n")
	report.WriteString(fmt.Sprintf("Total Repositories: %d\n", data.Summary.TotalRepositories))
	report.WriteString(fmt.Sprintf("Total SBOMs: %d\n", data.Summary.TotalSBOMs))
	report.WriteString(fmt.Sprintf("Total Components: %d\n", data.Summary.TotalComponents))
	report.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n\n", data.Summary.TotalVulns))

	// Vulnerability breakdown
	report.WriteString("VULNERABILITY BREAKDOWN\n")
	report.WriteString("-----------------------\n")
	for severity, count := range data.Summary.VulnsBySeverity {
		report.WriteString(fmt.Sprintf("%s: %d\n", strings.Title(severity), count))
	}
	report.WriteString("\n")

	// Language distribution
	if len(data.Summary.LanguageDistribution) > 0 {
		report.WriteString("LANGUAGE DISTRIBUTION\n")
		report.WriteString("--------------------\n")
		for language, count := range data.Summary.LanguageDistribution {
			report.WriteString(fmt.Sprintf("%s: %d projects\n", language, count))
		}
		report.WriteString("\n")
	}

	// Top vulnerable repositories
	if len(data.Summary.TopVulnerableRepos) > 0 {
		report.WriteString("TOP VULNERABLE REPOSITORIES\n")
		report.WriteString("---------------------------\n")
		for i, repo := range data.Summary.TopVulnerableRepos {
			if i >= 5 {
				break
			} // Top 5
			report.WriteString(fmt.Sprintf("%d. %s - %d vulnerabilities (%d critical, %d high)\n",
				i+1, repo.RepoName, repo.TotalVulns, repo.CriticalVulns, repo.HighVulns))
		}
		report.WriteString("\n")
	}

	// Repository details
	report.WriteString("REPOSITORY DETAILS\n")
	report.WriteString("------------------\n")
	for _, repo := range data.Repositories {
		report.WriteString(fmt.Sprintf("\nRepository: %s\n", repo.RepoName))
		report.WriteString(fmt.Sprintf("  Modules: %d\n", repo.ModuleCount))
		report.WriteString(fmt.Sprintf("  Components: %d\n", repo.TotalComponents))
		report.WriteString(fmt.Sprintf("  Vulnerabilities: %d\n", repo.TotalVulns))
		report.WriteString(fmt.Sprintf("  Risk Level: %s\n", repo.RiskLevel))
		report.WriteString(fmt.Sprintf("  Last Scan: %s\n", repo.LastScanDate.Format("2006-01-02 15:04")))
	}

	return report.String()
}

func getContentType(reportType string) string {
	switch reportType {
	case "pdf":
		return "application/pdf"
	case "csv":
		return "text/csv"
	case "excel":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	default:
		return "application/octet-stream"
	}
}
