package service

import (
	"fmt"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
)

type ScanService struct {
	database *db.Database
}

func NewScanService(db *db.Database) *ScanService {
	return &ScanService{database: db}
}

// Scan management handlers
func (ds *ScanService) HandleAPIStartScan(c *fiber.Ctx) error {
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

func (ds *ScanService) HandleAPIScanStatus(c *fiber.Ctx) error {
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

func (ds *ScanService) HandleAPIRescanSBOM(c *fiber.Ctx) error {
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
func (ds *ScanService) HandleAPIRescanRepository(c *fiber.Ctx) error {
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
func (ds *ScanService) executeScan(scanID, repoPath, repoName, modulePath, scanType string) {
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

func (ds *ScanService) HandleAPIScanResults(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 20)
	results, err := ds.database.GetLatestScanResults(limit)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get scan results"})
	}
	return c.JSON(results)
}
