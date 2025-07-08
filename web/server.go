package web

import (
	"fmt"
	"net/http"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"oss-compliance-scanner/web/service"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
)

// AppServer represents the web dashboard server
type AppServer struct {
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

// NewAppServer creates a new dashboard server instance
func NewAppServer(database *db.Database, port string) *AppServer {
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

	server := &AppServer{
		app:      app,
		database: database,
		port:     port,
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures all web routes
func (ds *AppServer) setupRoutes() {
	dashboardService := service.NewDashboardService(ds.database)
	policyService := service.NewPolicyService(ds.database)
	reportService := service.NewReportService(ds.database)
	scanService := service.NewScanService(ds.database)
	settingService := service.NewSettingService(ds.database)
	notificationService := service.NewNotificationService(ds.database)
	vulnerabilityService := service.NewVulnerabilityService(ds.database)
	sbomService := service.NewSBOMService(ds.database)
	healthService := service.NewHealthService(ds.database)

	// Static files
	ds.app.Static("/static", "./web/static")

	// Web pages
	ds.app.Get("/", ds.HandleDashboard)
	ds.app.Get("/sboms", ds.HandleSBOMs)
	ds.app.Get("/sboms/:id", ds.HandleSBOMDetail)
	ds.app.Get("/vulnerabilities", ds.handleVulnerabilities)
	ds.app.Get("/policies", ds.handlePolicies)
	ds.app.Get("/violations", ds.handleViolations)
	ds.app.Get("/reports", ds.handleReports)
	ds.app.Get("/admin", ds.handleAdmin)

	// API endpoints
	api := ds.app.Group("/api/v1")
	api.Get("/health", healthService.HandleHealthCheck)
	api.Get("/stats", dashboardService.HandleStats)
	api.Get("/sboms", sbomService.HandleAPISBOMs)
	api.Get("/sboms/:id", sbomService.HandleAPISBOMDetail)
	api.Get("/sboms/:id/components", sbomService.HandleAPIComponents)
	api.Get("/sboms/:id/vulnerabilities", vulnerabilityService.HandleAPIVulnerabilities)
	api.Get("/vulnerabilities", vulnerabilityService.HandleAPIVulnerabilities)
	api.Get("/violations", vulnerabilityService.HandleAPIViolations)
	api.Get("/scan-results", scanService.HandleAPIScanResults)

	// Policy management API
	api.Get("/policies/licenses", policyService.HandleAPILicensePolicies)
	api.Get("/policies/vulnerabilities", policyService.HandleAPIVulnerabilityPolicies)
	api.Post("/policies/licenses", policyService.HandleAPICreateLicensePolicy)
	api.Post("/policies/vulnerabilities", policyService.HandleAPICreateVulnerabilityPolicy)
	api.Delete("/policies/licenses/:id", policyService.HandleAPIDeleteLicensePolicy)
	api.Delete("/policies/vulnerabilities/:id", policyService.HandleAPIDeleteVulnerabilityPolicy)

	// Violation management API
	api.Put("/violations/:id/resolve", vulnerabilityService.HandleAPIResolveViolation)
	api.Put("/violations/:id/ignore", vulnerabilityService.HandleAPIIgnoreViolation)

	// Settings API
	api.Get("/settings", settingService.HandleAPIGetSettings)
	api.Put("/settings", settingService.HandleAPIPutSettings)

	// Scan API
	api.Post("/scan/start", scanService.HandleAPIStartScan)
	api.Get("/scan/status/:id", scanService.HandleAPIScanStatus)
	api.Post("/sboms/:id/rescan", scanService.HandleAPIRescanSBOM)
	api.Post("/repositories/:name/rescan", scanService.HandleAPIRescanRepository)
	api.Get("/sboms/:id/download", sbomService.HandleAPISBOMDownload)
	api.Get("/components/:id", sbomService.HandleAPIComponentDetail)
	api.Get("/sboms/:id/licenses", sbomService.HandleAPILicensesBySBOM)

	// Delete API
	api.Delete("/sboms/:id", sbomService.HandleAPIDeleteSBOM)
	api.Delete("/sboms", sbomService.HandleAPIDeleteSBOMs)
	api.Delete("/repositories/:name", sbomService.HandleAPIDeleteRepository)

	// Health check API
	api.Get("/health/db", healthService.HandleAPIHealthDB)
	api.Get("/health/scanner", healthService.HandleAPIHealthScanner)
	api.Get("/health/notifier", healthService.HandleAPIHealthNotifier)

	// Notification test API
	api.Post("/notifications/slack/test", notificationService.HandleAPISlackTest)

	// Report generation API
	api.Get("/reports", reportService.HandleAPIReports)
	api.Post("/reports", reportService.HandleAPICreateReport)
	api.Get("/reports/:id", reportService.HandleAPIReportDetail)
	api.Get("/reports/:id/download", reportService.HandleAPIReportDownload)
	api.Delete("/reports/:id", reportService.HandleAPIDeleteReport)
}

// Start starts the web server
func (ds *AppServer) Start() error {
	fmt.Printf("🌐 Starting OSS Compliance Dashboard on port %s\n", ds.port)
	return ds.app.Listen(":" + ds.port)
}

// Stop gracefully stops the web server
func (ds *AppServer) Stop() error {
	return ds.app.Shutdown()
}

// Test sends a test request to the server (for testing purposes)
func (ds *AppServer) Test(req *http.Request) (*http.Response, error) {
	return ds.app.Test(req)
}
