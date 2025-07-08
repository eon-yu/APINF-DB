package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"oss-compliance-scanner/config"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"oss-compliance-scanner/notifier"
	"oss-compliance-scanner/policy"
	"oss-compliance-scanner/scanner"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	repoPath     string
	modulePath   string
	outputFormat string
	configPath   string
	skipSBOM     bool
	skipVuln     bool
	notify       bool
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a repository or module for OSS compliance issues",
	Long: `Scan 명령어는 지정된 레포지토리나 모듈에서 오픈소스 라이브러리의
취약점과 라이선스 위반을 검사합니다.

스캔 과정:
1. Syft를 이용한 SBOM 생성
2. Grype를 이용한 취약점 스캔  
3. 정책 위반 분석
4. 결과 저장 및 알림 전송

예제:
  # 현재 디렉토리 스캔
  oss-compliance-scanner scan

  # 특정 레포지토리 스캔
  oss-compliance-scanner scan --repo /path/to/repo

  # 특정 모듈만 스캔
  oss-compliance-scanner scan --repo /path/to/repo --module frontend/app

  # SBOM 생성 없이 기존 결과로 취약점만 스캔
  oss-compliance-scanner scan --skip-sbom

  # 알림 비활성화
  oss-compliance-scanner scan --no-notify`,
	Run: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Add flags
	scanCmd.Flags().StringVarP(&repoPath, "repo", "r", ".", "Repository path to scan")
	scanCmd.Flags().StringVarP(&modulePath, "module", "m", "", "Specific module path to scan (relative to repo)")
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (table, json, yaml)")
	scanCmd.Flags().BoolVar(&skipSBOM, "skip-sbom", false, "Skip SBOM generation")
	scanCmd.Flags().BoolVar(&skipVuln, "skip-vuln", false, "Skip vulnerability scanning")
	scanCmd.Flags().BoolVar(&notify, "notify", true, "Send notifications on violations")

	// Bind flags to viper
	viper.BindPFlag("scan.repo", scanCmd.Flags().Lookup("repo"))
	viper.BindPFlag("scan.module", scanCmd.Flags().Lookup("module"))
	viper.BindPFlag("scan.output", scanCmd.Flags().Lookup("output"))
	viper.BindPFlag("scan.skip-sbom", scanCmd.Flags().Lookup("skip-sbom"))
	viper.BindPFlag("scan.skip-vuln", scanCmd.Flags().Lookup("skip-vuln"))
	viper.BindPFlag("scan.notify", scanCmd.Flags().Lookup("notify"))
}

func runScan(cmd *cobra.Command, args []string) {
	if verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Printf("Starting scan with parameters:")
		log.Printf("  Repository: %s", repoPath)
		log.Printf("  Module: %s", modulePath)
		log.Printf("  Output format: %s", outputFormat)
		log.Printf("  Skip SBOM: %t", skipSBOM)
		log.Printf("  Skip Vulnerability: %t", skipVuln)
		log.Printf("  Notify: %t", notify)
	}

	// Convert relative path to absolute
	absRepoPath, err := filepath.Abs(repoPath)
	if err != nil {
		log.Fatalf("Failed to resolve repository path: %v", err)
	}

	// Validate repository path exists
	if _, err := os.Stat(absRepoPath); os.IsNotExist(err) {
		log.Fatalf("Repository path does not exist: %s", absRepoPath)
	}

	// Create scan context
	scanCtx := &ScanContext{
		RepoPath:     absRepoPath,
		ModulePath:   modulePath,
		OutputFormat: outputFormat,
		ConfigPath:   cfgFile,
		SkipSBOM:     skipSBOM,
		SkipVuln:     skipVuln,
		Notify:       notify,
		Verbose:      verbose,
	}

	// Execute scan
	if err := executeScan(scanCtx); err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Println("✅ Scan completed successfully!")
}

// ScanContext holds all the context information for a scan
type ScanContext struct {
	RepoPath     string
	ModulePath   string
	OutputFormat string
	ConfigPath   string
	SkipSBOM     bool
	SkipVuln     bool
	Notify       bool
	Verbose      bool

	// Initialized components
	Config       *config.Config
	Database     *db.Database
	SyftScanner  *scanner.SyftScanner
	GrypeScanner *scanner.GrypeScanner
	PolicyEngine *policy.PolicyEngine
	Notifier     *notifier.SlackNotifier
}

// executeScan performs the actual scanning process
func executeScan(ctx *ScanContext) error {
	fmt.Println("🔍 Starting OSS Compliance Scan...")

	// Determine scan targets
	scanTargets := determineScanTargets(ctx)
	if len(scanTargets) == 0 {
		return fmt.Errorf("no scan targets found")
	}

	if ctx.Verbose {
		fmt.Printf("Found %d scan target(s):\n", len(scanTargets))
		for _, target := range scanTargets {
			fmt.Printf("  - %s\n", target)
		}
	}

	// Initialize components
	fmt.Println("🏗️  Initializing components...")

	if err := initializeComponents(ctx); err != nil {
		return fmt.Errorf("failed to initialize components: %w", err)
	}

	// Process targets (parallel or sequential based on target count)
	if len(scanTargets) > 1 && len(scanTargets) <= 10 {
		// Process targets in parallel for better performance
		fmt.Printf("\n🔄 Processing %d targets in parallel...\n", len(scanTargets))
		if err := processTargetsInParallel(ctx, scanTargets); err != nil {
			log.Printf("❌ Parallel processing failed: %v", err)
			// Fall back to sequential processing
			fmt.Println("🔄 Falling back to sequential processing...")
			processTargetsSequentially(ctx, scanTargets)
		}
	} else {
		// Process targets sequentially
		fmt.Printf("\n📦 Processing %d targets sequentially...\n", len(scanTargets))
		processTargetsSequentially(ctx, scanTargets)
	}

	fmt.Println("\n📊 Generating summary report...")
	if err := generateSummaryReport(ctx); err != nil {
		log.Printf("Warning: Failed to generate summary report: %v", err)
	}

	return nil
}

// initializeComponents initializes all necessary components for scanning
func initializeComponents(ctx *ScanContext) error {
	var err error

	// Load configuration
	ctx.Config, err = config.LoadConfig(ctx.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize database connection
	ctx.Database, err = db.NewDatabase(ctx.Config.Database.Driver, ctx.Config.Database.GetDSN())
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Initialize Syft scanner
	ctx.SyftScanner = scanner.NewSyftScanner(
		ctx.Config.Scanner.SyftPath,
		ctx.Config.Scanner.TempDir,
		ctx.Config.Scanner.CacheDir,
		ctx.Config.Scanner.TimeoutSeconds,
	)

	// Initialize Grype scanner
	ctx.GrypeScanner = scanner.NewGrypeScanner(
		ctx.Config.Scanner.GrypePath,
		ctx.Config.Scanner.TempDir,
		ctx.Config.Scanner.CacheDir,
		ctx.Config.Scanner.TimeoutSeconds,
	)

	// Initialize policy engine
	licensePolicies, err := ctx.Database.GetActiveLicensePolicies()
	if err != nil {
		log.Printf("Warning: Failed to load license policies: %v", err)
	}

	vulnerabilityPolicies, err := ctx.Database.GetActiveVulnerabilityPolicies()
	if err != nil {
		log.Printf("Warning: Failed to load vulnerability policies: %v", err)
	}

	ctx.PolicyEngine = policy.NewPolicyEngine(licensePolicies, vulnerabilityPolicies, ctx.Config.Policy.GlobalSettings)

	// Initialize notifier if notifications are enabled
	if ctx.Notify && ctx.Config.Notification.SlackWebhookURL != "" {
		ctx.Notifier = notifier.NewSlackNotifier(
			ctx.Config.Notification.SlackWebhookURL,
			ctx.Config.Notification.SlackChannel,
			"OSS-Compliance-Bot",
			":warning:",
		)
	}

	// Validate scanner installations
	scannerCtx := context.Background()
	if err := ctx.SyftScanner.ValidateInstallation(scannerCtx); err != nil {
		return fmt.Errorf("syft validation failed: %w", err)
	}
	if err := ctx.GrypeScanner.ValidateInstallation(scannerCtx); err != nil {
		return fmt.Errorf("grype validation failed: %w", err)
	}

	return nil
}

// determineScanTargets determines what directories/modules to scan
func determineScanTargets(ctx *ScanContext) []string {
	var targets []string

	if ctx.ModulePath != "" {
		// Scan specific module
		modulePath := filepath.Join(ctx.RepoPath, ctx.ModulePath)
		if _, err := os.Stat(modulePath); err == nil {
			targets = append(targets, modulePath)
		}
	} else {
		// Auto-discover modules/packages in the repository
		targets = autoDiscoverTargets(ctx.RepoPath)
	}

	return targets
}

// autoDiscoverTargets automatically discovers scannable targets in the repository
func autoDiscoverTargets(repoPath string) []string {
	var targets []string

	// First, check for workspace configuration files
	workspaceTargets := discoverWorkspaceTargets(repoPath)
	if len(workspaceTargets) > 0 {
		if verbose {
			log.Printf("Found workspace configuration, using defined modules")
		}
		return workspaceTargets
	}

	// Look for common package files that indicate a module
	packageFiles := []string{
		"package.json",     // Node.js
		"go.mod",           // Go
		"requirements.txt", // Python
		"Pipfile",          // Python
		"pom.xml",          // Java/Maven
		"build.gradle",     // Java/Gradle
		"Cargo.toml",       // Rust
		"composer.json",    // PHP
		"Gemfile",          // Ruby
		// Modern C++ package managers
		"conanfile.txt", // C++ Conan
		"conanfile.py",  // C++ Conan
		"vcpkg.json",    // C++ vcpkg
		// Build systems (could be C or C++)
		"CMakeLists.txt", // CMake (C/C++)
		"Makefile",       // Make (C/C++)
		"BUILD",          // Bazel (C/C++)
		"BUILD.bazel",    // Bazel (C/C++)
		"meson.build",    // Meson (C/C++)
		"configure.ac",   // Autotools (C/C++)
		"configure.in",   // Autotools (C/C++)
		"SConstruct",     // SCons (C/C++)
	}

	// Define maximum depth to prevent scanning too deep
	const maxDepth = 4
	rootDepth := strings.Count(repoPath, string(filepath.Separator))

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}

		// Calculate current depth
		currentDepth := strings.Count(path, string(filepath.Separator)) - rootDepth
		if currentDepth > maxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden directories and common build/cache directories
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") ||
				name == "node_modules" ||
				name == "vendor" ||
				name == "target" ||
				name == "build" ||
				name == "dist" ||
				name == "__pycache__" ||
				name == ".git" ||
				name == ".svn" ||
				name == ".hg" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this file indicates a package/module
		for _, packageFile := range packageFiles {
			if info.Name() == packageFile {
				// Add the directory containing this package file
				dir := filepath.Dir(path)
				targets = append(targets, dir)
				break
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Warning: Error walking repository: %v", err)
	}

	// If no targets found, scan the root directory
	if len(targets) == 0 {
		targets = append(targets, repoPath)
	}

	// Remove duplicates and sort by priority
	targets = removeDuplicates(targets)
	targets = sortTargetsByPriority(repoPath, targets)

	if verbose {
		log.Printf("Auto-discovered %d scan targets", len(targets))
		for i, target := range targets {
			relPath, _ := filepath.Rel(repoPath, target)
			if relPath == "." {
				relPath = "root"
			}
			log.Printf("  %d. %s", i+1, relPath)
		}
	}

	return targets
}

// processScanTarget processes a single scan target
func processScanTarget(ctx *ScanContext, targetPath string) error {
	scanStartTime := time.Now()

	relPath, _ := filepath.Rel(ctx.RepoPath, targetPath)
	if relPath == "." {
		relPath = "root"
	}

	repoName := filepath.Base(ctx.RepoPath)
	scannerCtx := context.Background()

	var sbomRecord *models.SBOM
	var sbomComponents []*models.Component
	var vulnerabilities []*models.Vulnerability

	// Step 1: Generate SBOM
	fmt.Printf("  📋 Generating SBOM for %s...\n", relPath)
	if !ctx.SkipSBOM {
		sbom, err := ctx.SyftScanner.GenerateSBOM(scannerCtx, targetPath, nil)
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}

		// Create SBOM record
		sbomRecord = &models.SBOM{
			RepoName:       repoName,
			ModulePath:     relPath,
			ScanDate:       time.Now(),
			SyftVersion:    "latest", // TODO: Get actual version
			RawSBOM:        string(sbom.RawSBOM),
			ComponentCount: 0, // Will be updated after components are parsed
		}

		// Save SBOM to database
		if err := ctx.Database.CreateSBOM(sbomRecord); err != nil {
			return fmt.Errorf("failed to save SBOM: %w", err)
		}

		// Parse and save components
		components, err := ctx.SyftScanner.ParseSBOMToComponents(sbomRecord)
		if err != nil {
			return fmt.Errorf("failed to parse SBOM components: %w", err)
		}

		// Update component count
		sbomRecord.ComponentCount = len(components)

		// Save components to database
		for _, comp := range components {
			if err := ctx.Database.CreateComponent(comp); err != nil {
				log.Printf("Warning: Failed to save component %s: %v", comp.Name, err)
				continue
			}
			sbomComponents = append(sbomComponents, comp)
		}

		fmt.Printf("    ✓ SBOM generated with %d components\n", len(components))
	} else {
		fmt.Printf("    ⏭️  SBOM generation skipped\n")
	}

	// Step 2: Scan vulnerabilities
	fmt.Printf("  🛡️  Scanning vulnerabilities for %s...\n", relPath)
	if !ctx.SkipVuln {
		vulns, err := ctx.GrypeScanner.ScanDirectory(scannerCtx, targetPath, nil)
		if err != nil {
			log.Printf("Warning: Failed to scan vulnerabilities: %v", err)
		} else {
			// Link vulnerabilities to components and save them
			for _, vuln := range vulns {
				// Find matching component by name (simple matching)
				var componentID int
				for _, comp := range sbomComponents {
					// Simple name matching - in production, more sophisticated matching would be needed
					if comp.Name != "" {
						componentID = comp.ID
						break
					}
				}

				if componentID > 0 {
					vuln.ComponentID = componentID
					if err := ctx.Database.CreateVulnerability(vuln); err != nil {
						log.Printf("Warning: Failed to save vulnerability %s: %v", vuln.VulnID, err)
						continue
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}

		fmt.Printf("    ✓ Vulnerability scan completed, found %d vulnerabilities\n", len(vulnerabilities))
	} else {
		fmt.Printf("    ⏭️  Vulnerability scan skipped\n")
	}

	// Step 3: Analyze policy compliance
	fmt.Printf("  📏 Analyzing policy compliance for %s...\n", relPath)
	var scanResult *models.ScanResult

	if sbomRecord != nil {
		result, err := ctx.PolicyEngine.EvaluateCompliance(sbomRecord, sbomComponents, vulnerabilities)
		if err != nil {
			log.Printf("Warning: Policy evaluation failed: %v", err)
		} else {
			// Convert policy evaluation result to scan result
			scanResult = &models.ScanResult{
				SBOMID:               sbomRecord.ID,
				RepoName:             repoName,
				ModulePath:           relPath,
				ScanStartTime:        scanStartTime,
				ScanEndTime:          time.Now(),
				Status:               models.ScanStatusCompleted,
				TotalComponents:      result.TotalComponents,
				VulnerabilitiesFound: result.TotalVulnerabilities,
				LicenseViolations:    result.Summary.LicenseViolations,
				CriticalVulns:        result.Summary.CriticalViolations,
				HighVulns:            result.Summary.HighViolations,
				MediumVulns:          result.Summary.MediumViolations,
				LowVulns:             result.Summary.LowViolations,
			}

			// Calculate overall risk
			scanResult.OverallRisk = scanResult.CalculateOverallRisk()

			if err := ctx.Database.CreateScanResult(scanResult); err != nil {
				log.Printf("Warning: Failed to save scan result: %v", err)
			}
		}
	}

	fmt.Printf("    ✓ Policy analysis completed\n")

	// Step 4: Send notifications
	if ctx.Notify && ctx.Notifier != nil && scanResult != nil {
		fmt.Printf("  📢 Sending notifications for %s...\n", relPath)

		// Check if there are violations to report
		if scanResult.VulnerabilitiesFound > 0 || scanResult.LicenseViolations > 0 {
			message := fmt.Sprintf("🚨 OSS Compliance Issues Found in %s/%s\n\n", repoName, relPath)
			message += fmt.Sprintf("📊 **Summary:**\n")
			message += fmt.Sprintf("• Total Components: %d\n", scanResult.TotalComponents)
			message += fmt.Sprintf("• Vulnerabilities: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
				scanResult.VulnerabilitiesFound, scanResult.CriticalVulns, scanResult.HighVulns,
				scanResult.MediumVulns, scanResult.LowVulns)
			message += fmt.Sprintf("• License Violations: %d\n", scanResult.LicenseViolations)
			message += fmt.Sprintf("• Overall Risk: %s\n", scanResult.OverallRisk)

			if err := ctx.Notifier.SendCustomMessage(message, ""); err != nil {
				log.Printf("Warning: Failed to send notification: %v", err)
			}
		}

		fmt.Printf("    ✓ Notifications sent\n")
	} else if ctx.Notify {
		fmt.Printf("  📢 Notifications for %s...\n", relPath)
		fmt.Printf("    ⏭️  No violations found or notifier not configured\n")
	}

	return nil
}

// generateSummaryReport generates and displays a summary of all scan results
func generateSummaryReport(ctx *ScanContext) error {
	// Get latest scan results
	results, err := ctx.Database.GetLatestScanResults(10)
	if err != nil {
		return fmt.Errorf("failed to get scan results: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No scan results found.")
		return nil
	}

	fmt.Printf("\n📋 **Scan Summary Report**\n")
	fmt.Printf("========================\n")

	totalComponents := 0
	totalVulns := 0
	totalLicenseViolations := 0

	for _, result := range results {
		fmt.Printf("\n🔍 **%s/%s**\n", result.RepoName, result.ModulePath)
		fmt.Printf("  • Components: %d\n", result.TotalComponents)
		fmt.Printf("  • Vulnerabilities: %d (C:%d, H:%d, M:%d, L:%d)\n",
			result.VulnerabilitiesFound, result.CriticalVulns, result.HighVulns,
			result.MediumVulns, result.LowVulns)
		fmt.Printf("  • License Violations: %d\n", result.LicenseViolations)
		fmt.Printf("  • Risk Level: %s\n", result.OverallRisk)
		fmt.Printf("  • Scan Time: %s\n", result.ScanStartTime.Format("2006-01-02 15:04:05"))

		totalComponents += result.TotalComponents
		totalVulns += result.VulnerabilitiesFound
		totalLicenseViolations += result.LicenseViolations
	}

	fmt.Printf("\n📊 **Overall Summary**\n")
	fmt.Printf("• Total Scanned Components: %d\n", totalComponents)
	fmt.Printf("• Total Vulnerabilities: %d\n", totalVulns)
	fmt.Printf("• Total License Violations: %d\n", totalLicenseViolations)

	return nil
}

// discoverWorkspaceTargets discovers targets from workspace configuration files
func discoverWorkspaceTargets(repoPath string) []string {
	var targets []string

	// Check for common workspace configuration files
	workspaceFiles := []string{
		"workspace.yaml",      // Generic workspace
		"lerna.json",          // Lerna monorepo
		"nx.json",             // Nx monorepo
		"rush.json",           // Rush monorepo
		"pnpm-workspace.yaml", // PNPM workspace
		"yarn.lock",           // Yarn workspace (check for workspaces in package.json)
	}

	for _, workspaceFile := range workspaceFiles {
		workspacePath := filepath.Join(repoPath, workspaceFile)
		if _, err := os.Stat(workspacePath); err == nil {
			if verbose {
				log.Printf("Found workspace file: %s", workspaceFile)
			}

			// Parse workspace configuration based on file type
			switch workspaceFile {
			case "package.json":
				// Handle package.json with workspaces
				targets = append(targets, parsePackageJsonWorkspaces(workspacePath)...)
			case "lerna.json":
				targets = append(targets, parseLernaWorkspaces(workspacePath)...)
			case "pnpm-workspace.yaml":
				targets = append(targets, parsePnpmWorkspaces(workspacePath)...)
			default:
				// For other workspace files, fall back to auto-discovery
				continue
			}
		}
	}

	// Convert relative paths to absolute paths
	var absoluteTargets []string
	for _, target := range targets {
		if !filepath.IsAbs(target) {
			target = filepath.Join(repoPath, target)
		}
		// Verify the target directory exists
		if _, err := os.Stat(target); err == nil {
			absoluteTargets = append(absoluteTargets, target)
		}
	}

	return absoluteTargets
}

// parsePackageJsonWorkspaces parses package.json for workspace definitions
func parsePackageJsonWorkspaces(packagePath string) []string {
	// This is a simplified implementation
	// In a real implementation, you would parse the JSON and extract workspace patterns
	return []string{}
}

// parseLernaWorkspaces parses lerna.json for workspace definitions
func parseLernaWorkspaces(lernaPath string) []string {
	// This is a simplified implementation
	// In a real implementation, you would parse the JSON and extract packages patterns
	return []string{}
}

// parsePnpmWorkspaces parses pnpm-workspace.yaml for workspace definitions
func parsePnpmWorkspaces(workspacePath string) []string {
	// This is a simplified implementation
	// In a real implementation, you would parse the YAML and extract packages patterns
	return []string{}
}

// sortTargetsByPriority sorts targets by priority (root level first, then by depth)
func sortTargetsByPriority(repoPath string, targets []string) []string {
	// Create a map to store targets with their priority scores
	type targetInfo struct {
		path   string
		depth  int
		isRoot bool
	}

	var targetInfos []targetInfo
	rootDepth := strings.Count(repoPath, string(filepath.Separator))

	for _, target := range targets {
		depth := strings.Count(target, string(filepath.Separator)) - rootDepth
		isRoot := target == repoPath

		targetInfos = append(targetInfos, targetInfo{
			path:   target,
			depth:  depth,
			isRoot: isRoot,
		})
	}

	// Sort by priority: root first, then by depth (shallower first)
	for i := 0; i < len(targetInfos); i++ {
		for j := i + 1; j < len(targetInfos); j++ {
			// Root directories have highest priority
			if targetInfos[i].isRoot && !targetInfos[j].isRoot {
				continue
			}
			if !targetInfos[i].isRoot && targetInfos[j].isRoot {
				targetInfos[i], targetInfos[j] = targetInfos[j], targetInfos[i]
				continue
			}

			// Among non-root directories, prioritize by depth (shallower first)
			if targetInfos[i].depth > targetInfos[j].depth {
				targetInfos[i], targetInfos[j] = targetInfos[j], targetInfos[i]
			}
		}
	}

	// Extract sorted paths
	var sortedTargets []string
	for _, info := range targetInfos {
		sortedTargets = append(sortedTargets, info.path)
	}

	return sortedTargets
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// processTargetsSequentially processes targets one by one
func processTargetsSequentially(ctx *ScanContext, targets []string) {
	for i, target := range targets {
		fmt.Printf("\n📦 Processing target %d/%d: %s\n", i+1, len(targets), target)

		if err := processScanTarget(ctx, target); err != nil {
			log.Printf("❌ Failed to process target %s: %v", target, err)
			continue
		}

		fmt.Printf("✅ Completed target: %s\n", target)
	}
}

// processTargetsInParallel processes multiple targets concurrently
func processTargetsInParallel(ctx *ScanContext, targets []string) error {
	// Limit concurrency to avoid overwhelming the system
	const maxConcurrency = 3
	semaphore := make(chan struct{}, maxConcurrency)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []error

	for i, target := range targets {
		wg.Add(1)
		go func(index int, targetPath string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fmt.Printf("\n📦 Processing target %d/%d: %s\n", index+1, len(targets), targetPath)

			if err := processScanTarget(ctx, targetPath); err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("target %s: %w", targetPath, err))
				mu.Unlock()
				log.Printf("❌ Failed to process target %s: %v", targetPath, err)
				return
			}

			fmt.Printf("✅ Completed target: %s\n", targetPath)
		}(i, target)
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("failed to process %d targets: %v", len(errors), errors)
	}

	return nil
}
