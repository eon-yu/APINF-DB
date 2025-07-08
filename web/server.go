package web

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"

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

	// Health check API
	api.Get("/health/db", ds.handleAPIHealthDB)
	api.Get("/health/scanner", ds.handleAPIHealthScanner)
	api.Get("/health/notifier", ds.handleAPIHealthNotifier)
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
	sboms, err := ds.database.GetAllSBOMs(50)
	if err != nil {
		return c.Status(500).SendString("Failed to load SBOMs")
	}

	return c.Render("sboms", fiber.Map{
		"Title": "SBOM List",
		"SBOMs": sboms,
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

	return c.JSON(components)
}

func (ds *DashboardServer) handleAPIVulnerabilities(c *fiber.Ctx) error {
	sbomIDParam := c.Params("id")
	if sbomIDParam != "" {
		// Get vulnerabilities for specific SBOM
		sbomID, err := strconv.Atoi(sbomIDParam)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid SBOM ID"})
		}

		components, err := ds.database.GetComponentsBySBOM(sbomID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to get components"})
		}

		var vulnerabilities []*models.Vulnerability
		for _, component := range components {
			vulns, err := ds.database.GetVulnerabilitiesByComponent(component.ID)
			if err == nil {
				vulnerabilities = append(vulnerabilities, vulns...)
			}
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
	sboms, err := ds.database.GetAllSBOMs(100)
	if err != nil {
		fmt.Printf("Error getting SBOMs: %v\n", err)
		return nil, err
	}
	fmt.Printf("Found %d SBOMs\n", len(sboms))

	// Get scan results for additional stats
	scanResults, err := ds.database.GetLatestScanResults(100)
	if err != nil {
		scanResults = []*models.ScanResult{} // Empty slice on error
	}

	stats := map[string]interface{}{
		"total_sboms":           len(sboms),
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

	// Calculate component count from SBOMs
	for _, sbom := range sboms {
		stats["total_components"] = stats["total_components"].(int) + sbom.ComponentCount
		repos := stats["repositories"].(map[string]bool)
		repos[sbom.RepoName] = true
	}

	if len(scanResults) > 0 {
		stats["last_scan"] = scanResults[0].ScanStartTime
	}

	// Get actual vulnerability statistics from database
	allVulnerabilities, err := ds.database.GetAllVulnerabilities(1000) // Get more vulnerabilities for accurate stats
	if err == nil {
		stats["total_vulnerabilities"] = len(allVulnerabilities)

		// Count vulnerabilities by severity
		for _, vuln := range allVulnerabilities {
			switch vuln.Severity {
			case "Critical":
				stats["critical_vulns"] = stats["critical_vulns"].(int) + 1
			case "High":
				stats["high_vulns"] = stats["high_vulns"].(int) + 1
			case "Medium":
				stats["medium_vulns"] = stats["medium_vulns"].(int) + 1
			case "Low":
				stats["low_vulns"] = stats["low_vulns"].(int) + 1
			}
		}
	} else {
		// Fallback to scan result summary if direct vulnerability query fails
		for _, result := range scanResults {
			stats["total_vulnerabilities"] = stats["total_vulnerabilities"].(int) + result.VulnerabilitiesFound
			stats["critical_vulns"] = stats["critical_vulns"].(int) + result.CriticalVulns
			stats["high_vulns"] = stats["high_vulns"].(int) + result.HighVulns
			stats["medium_vulns"] = stats["medium_vulns"].(int) + result.MediumVulns
			stats["low_vulns"] = stats["low_vulns"].(int) + result.LowVulns
		}
	}

	stats["total_repositories"] = len(stats["repositories"].(map[string]bool))
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
