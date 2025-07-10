package util

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"oss-compliance-scanner/config"
	"oss-compliance-scanner/notifier"
	"oss-compliance-scanner/scanner"
	"path/filepath"
	"strings"
	"sync"
)

// ScanContext holds all the context information for a scan
type ScanContext struct {
	RepoPath   string
	ModulePath string
	SkipSBOM   bool
	SkipVuln   bool
	Notify     bool
	Verbose    bool

	// Initialized components
	Config      *config.Config
	SyftScanner *scanner.SyftScanner
	Notifier    *notifier.SlackNotifier
}

// executeScan performs the actual scanning process
func ExecuteScan(ctx *ScanContext) error {
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

	return nil
}

// initializeComponents initializes all necessary components for scanning
func initializeComponents(ctx *ScanContext) error {

	// Load configuration
	ctx.Config = config.GetConfig()

	// Initialize Syft scanner
	ctx.SyftScanner = scanner.NewSyftScanner(
		ctx.Config.Scanner.SyftPath,
		ctx.Config.Scanner.TempDir,
		ctx.Config.Scanner.CacheDir,
		ctx.Config.Scanner.TimeoutSeconds,
	)

	// Initialize notifier if notifications are enabled
	// if ctx.Notify && ctx.Config.Notification.SlackWebhookURL != "" {
	// 	ctx.Notifier = notifier.NewSlackNotifier(
	// 		ctx.Config.Notification.SlackWebhookURL,
	// 		"OSS-Compliance-Bot",
	// 		ctx.Config.Notification.SlackChannel,
	// 		":warning:",
	// 	)
	// }
	// Validate scanner installations
	scannerCtx := context.Background()
	if err := ctx.SyftScanner.ValidateInstallation(scannerCtx); err != nil {
		return fmt.Errorf("syft validation failed: %w", err)
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
		targets = autoDiscoverTargets(ctx.RepoPath, ctx.Verbose)
	}

	return targets
}

// autoDiscoverTargets automatically discovers scannable targets in the repository
func autoDiscoverTargets(repoPath string, verbose bool) []string {
	var targets []string

	// First, check for workspace configuration files
	workspaceTargets := discoverWorkspaceTargets(repoPath, verbose)
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

	relPath, _ := filepath.Rel(ctx.RepoPath, targetPath)
	if relPath == "." {
		relPath = "root"
	}

	// Step 1: Generate SBOM
	fmt.Printf("  📋 Generating SBOM for %s...\n", relPath)

	err := ctx.SyftScanner.GenerateSBOM(context.Background(), targetPath)
	if err != nil {
		return fmt.Errorf("failed to generate SBOM: %w", err)
	}

	return nil
}

// discoverWorkspaceTargets discovers targets from workspace configuration files
func discoverWorkspaceTargets(repoPath string, verbose bool) []string {
	var targets []string

	// Check for common workspace configuration files
	workspaceFiles := []string{
		"package.json",        // Package.json with workspaces field
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
				targets = append(targets, parsePackageJsonWorkspaces(workspacePath, verbose)...)
			case "lerna.json":
				targets = append(targets, parseLernaWorkspaces(workspacePath, verbose)...)
			case "pnpm-workspace.yaml":
				targets = append(targets, parsePnpmWorkspaces(workspacePath, verbose)...)
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
func parsePackageJsonWorkspaces(packagePath string, verbose bool) []string {
	data, err := os.ReadFile(packagePath)
	if err != nil {
		if verbose {
			log.Printf("Failed to read package.json: %v", err)
		}
		return []string{}
	}

	var packageJSON struct {
		Workspaces []string `json:"workspaces"`
	}

	if err := json.Unmarshal(data, &packageJSON); err != nil {
		if verbose {
			log.Printf("Failed to parse package.json: %v", err)
		}
		return []string{}
	}

	return packageJSON.Workspaces
}

// parseLernaWorkspaces parses lerna.json for workspace definitions
func parseLernaWorkspaces(lernaPath string, verbose bool) []string {
	// This is a simplified implementation
	// In a real implementation, you would parse the JSON and extract packages patterns
	return []string{}
}

// parsePnpmWorkspaces parses pnpm-workspace.yaml for workspace definitions
func parsePnpmWorkspaces(workspacePath string, verbose bool) []string {
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
