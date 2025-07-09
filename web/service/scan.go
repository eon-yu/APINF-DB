package service

import (
	"context"
	"fmt"
	"log"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"path/filepath"
	"strconv"
	"time"

	"oss-compliance-scanner/config"
	"oss-compliance-scanner/scanner"
	"oss-compliance-scanner/util"

	"github.com/gofiber/fiber/v2"
)

type ScanRequest struct {
	RepoPath   string `json:"repository_path"`
	RepoName   string `json:"repository_name"`
	ModulePath string `json:"module_path"`
	ScanType   string `json:"scan_type"`
}
type ScanService struct {
	database *db.Database
}

func NewScanService(db *db.Database) *ScanService {
	return &ScanService{database: db}
}

// Scan management handlers
func (ds *ScanService) HandleAPIStartScan(c *fiber.Ctx) error {

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
		util.ExecuteScan(&util.ScanContext{
			RepoPath:   req.RepoPath,
			ModulePath: req.ModulePath,
			SkipSBOM:   false,
			SkipVuln:   false,
			Notify:     true,
			Verbose:    true,
		})
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
	// Use Background context for tool executions
	ctx := context.Background()

	// Resolve target path – if modulePath is provided join with repoPath
	var targetPath string
	if repoPath != "" {
		targetPath = repoPath
		if modulePath != "" {
			targetPath = filepath.Join(repoPath, modulePath)
		}
	}

	startTime := time.Now()
	log.Printf("[%s] ▶️  Scan started – repo:%s module:%s path:%s", scanID, repoName, modulePath, targetPath)

	// Load configuration (defaults if no file)
	cfg := config.GetConfig()

	// Initialize scanners
	syftScanner := scanner.NewSyftScanner(cfg.Scanner.SyftPath, cfg.Scanner.TempDir, cfg.Scanner.CacheDir, cfg.Scanner.TimeoutSeconds)
	grypeScanner := scanner.NewGrypeScanner(cfg.Scanner.GrypePath, cfg.Scanner.TempDir, cfg.Scanner.CacheDir, cfg.Scanner.TimeoutSeconds)

	var (
		sbom            *models.SBOM
		components      []*models.Component
		vulnerabilities []*models.Vulnerability
	)

	// 1️⃣ SBOM generation ------------------------------------------------------
	if scanType == "sbom" || scanType == "both" {
		if targetPath == "" {
			log.Printf("[%s] ⚠️  No repo path provided – skipping SBOM generation", scanID)
		} else {
			var err error
			sbom, err = syftScanner.GenerateSBOM(ctx, targetPath, nil)
			if err != nil {
				log.Printf("[%s] ❌ SBOM generation failed: %v", scanID, err)
			} else {
				sbom.RepoName = repoName
				sbom.ModulePath = modulePath
				// Persist SBOM
				if err := ds.database.CreateSBOM(sbom); err != nil {
					log.Printf("[%s] ❌ Failed to store SBOM: %v", scanID, err)
				}

				// Parse & store components
				components, err = syftScanner.ParseSBOMToComponents(sbom)
				if err != nil {
					log.Printf("[%s] ⚠️  Failed to parse components: %v", scanID, err)
				} else {
					for _, comp := range components {
						if err := ds.database.CreateComponent(comp); err != nil {
							log.Printf("[%s] ⚠️  Failed to store component %s@%s: %v", scanID, comp.Name, comp.Version, err)
						}
					}
				}
			}
		}
	}

	// 2️⃣ Vulnerability scanning ----------------------------------------------
	if scanType == "vuln" || scanType == "both" {
		if targetPath == "" {
			log.Printf("[%s] ⚠️  No repo path provided – skipping vulnerability scan", scanID)
		} else {
			var err error
			vulnerabilities, err = grypeScanner.ScanDirectory(ctx, targetPath, nil)
			if err != nil {
				log.Printf("[%s] ❌ Vulnerability scan failed: %v", scanID, err)
			} else {
				// Build component lookup for mapping (name@version -> ID)
				compLookup := make(map[string]int)
				for _, comp := range components {
					key := fmt.Sprintf("%s@%s", comp.Name, comp.Version)
					compLookup[key] = comp.ID
				}

				for _, vuln := range vulnerabilities {
					// Map to component via artifact metadata if possible
					art, ok := vuln.Metadata["artifact"].(map[string]any)
					if ok {
						name, _ := art["name"].(string)
						version, _ := art["version"].(string)
						if name != "" && version != "" {
							if id, ok := compLookup[fmt.Sprintf("%s@%s", name, version)]; ok {
								vuln.ComponentID = id
							}
						}
					}

					if vuln.ComponentID == 0 {
						// Could not map – skip storing to maintain referential integrity
						continue
					}

					if err := ds.database.CreateVulnerability(vuln); err != nil {
						log.Printf("[%s] ⚠️  Failed to store vulnerability %s: %v", scanID, vuln.VulnID, err)
					}
				}
			}
		}
	}

	// 3️⃣ Store scan result ----------------------------------------------------
	endTime := time.Now()
	result := &models.ScanResult{
		SBOMID:               0,
		RepoName:             repoName,
		ModulePath:           modulePath,
		ScanStartTime:        startTime,
		ScanEndTime:          endTime,
		Status:               models.ScanStatusCompleted,
		TotalComponents:      len(components),
		VulnerabilitiesFound: len(vulnerabilities),
	}

	if sbom != nil {
		result.SBOMID = sbom.ID
	}

	// Count severities
	if len(vulnerabilities) > 0 {
		sevCounts := grypeScanner.CountVulnerabilitiesBySeverity(vulnerabilities)
		result.CriticalVulns = sevCounts["Critical"]
		result.HighVulns = sevCounts["High"]
		result.MediumVulns = sevCounts["Medium"]
		result.LowVulns = sevCounts["Low"]
	}

	result.OverallRisk = result.CalculateOverallRisk()

	if err := ds.database.CreateScanResult(result); err != nil {
		log.Printf("[%s] ⚠️  Failed to store scan_result: %v", scanID, err)
	}

	log.Printf("[%s] ✅ Scan completed (components:%d vulns:%d)", scanID, len(components), len(vulnerabilities))

}

func (ds *ScanService) HandleAPIScanResults(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 20)
	results, err := ds.database.GetLatestScanResults(limit)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to get scan results"})
	}
	return c.JSON(results)
}
