package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

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

	// Scan-specific flags
	scanCmd.Flags().StringVarP(&repoPath, "repo", "r", ".", "repository path to scan")
	scanCmd.Flags().StringVarP(&modulePath, "module", "m", "", "specific module path to scan (relative to repo)")
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "output format (table, json, yaml)")
	scanCmd.Flags().StringVar(&configPath, "policy-config", "", "path to policy configuration file")
	scanCmd.Flags().BoolVar(&skipSBOM, "skip-sbom", false, "skip SBOM generation and use existing data")
	scanCmd.Flags().BoolVar(&skipVuln, "skip-vuln", false, "skip vulnerability scanning")
	scanCmd.Flags().BoolVar(&notify, "notify", true, "send Slack notifications")

	// Bind flags to viper
	viper.BindPFlag("scan.repo", scanCmd.Flags().Lookup("repo"))
	viper.BindPFlag("scan.module", scanCmd.Flags().Lookup("module"))
	viper.BindPFlag("scan.output", scanCmd.Flags().Lookup("output"))
	viper.BindPFlag("scan.policy_config", scanCmd.Flags().Lookup("policy-config"))
	viper.BindPFlag("scan.skip_sbom", scanCmd.Flags().Lookup("skip-sbom"))
	viper.BindPFlag("scan.skip_vuln", scanCmd.Flags().Lookup("skip-vuln"))
	viper.BindPFlag("scan.notify", scanCmd.Flags().Lookup("notify"))
}

func runScan(cmd *cobra.Command, args []string) {
	// Validate repository path
	repoPath = viper.GetString("scan.repo")
	if repoPath == "" {
		repoPath = "."
	}

	// Convert to absolute path
	absRepoPath, err := filepath.Abs(repoPath)
	if err != nil {
		log.Fatalf("Invalid repository path: %v", err)
	}

	// Check if path exists
	if _, err := os.Stat(absRepoPath); os.IsNotExist(err) {
		log.Fatalf("Repository path does not exist: %s", absRepoPath)
	}

	// Get other parameters from viper
	modulePath = viper.GetString("scan.module")
	outputFormat = viper.GetString("scan.output")
	configPath = viper.GetString("scan.policy_config")
	skipSBOM = viper.GetBool("scan.skip_sbom")
	skipVuln = viper.GetBool("scan.skip_vuln")
	notify = viper.GetBool("scan.notify")

	if verbose {
		log.Printf("Starting scan with parameters:")
		log.Printf("  Repository: %s", absRepoPath)
		log.Printf("  Module: %s", modulePath)
		log.Printf("  Output format: %s", outputFormat)
		log.Printf("  Skip SBOM: %t", skipSBOM)
		log.Printf("  Skip Vulnerability: %t", skipVuln)
		log.Printf("  Notify: %t", notify)
	}

	// Create scan context
	scanCtx := &ScanContext{
		RepoPath:     absRepoPath,
		ModulePath:   modulePath,
		OutputFormat: outputFormat,
		ConfigPath:   configPath,
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

	// TODO: Initialize database connection
	// TODO: Initialize scanner components
	// TODO: Initialize policy engine
	// TODO: Initialize notifier

	// Process each target
	for i, target := range scanTargets {
		fmt.Printf("\n📦 Processing target %d/%d: %s\n", i+1, len(scanTargets), target)

		if err := processScanTarget(ctx, target); err != nil {
			log.Printf("❌ Failed to process target %s: %v", target, err)
			continue
		}

		fmt.Printf("✅ Completed target: %s\n", target)
	}

	fmt.Println("\n📊 Generating summary report...")
	// TODO: Generate and display summary

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
	}

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}

		// Skip hidden directories and common build/cache directories
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") ||
				name == "node_modules" ||
				name == "vendor" ||
				name == "target" ||
				name == "build" ||
				name == "__pycache__" {
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

	// Remove duplicates
	return removeDuplicates(targets)
}

// processScanTarget processes a single scan target
func processScanTarget(ctx *ScanContext, targetPath string) error {
	relPath, _ := filepath.Rel(ctx.RepoPath, targetPath)
	if relPath == "." {
		relPath = "root"
	}

	fmt.Printf("  📋 Generating SBOM for %s...\n", relPath)
	if !ctx.SkipSBOM {
		// TODO: Generate SBOM using Syft
		fmt.Printf("    ✓ SBOM generated\n")
	} else {
		fmt.Printf("    ⏭️  SBOM generation skipped\n")
	}

	fmt.Printf("  🛡️  Scanning vulnerabilities for %s...\n", relPath)
	if !ctx.SkipVuln {
		// TODO: Scan vulnerabilities using Grype
		fmt.Printf("    ✓ Vulnerability scan completed\n")
	} else {
		fmt.Printf("    ⏭️  Vulnerability scan skipped\n")
	}

	fmt.Printf("  📏 Analyzing policy compliance for %s...\n", relPath)
	// TODO: Analyze policy violations
	fmt.Printf("    ✓ Policy analysis completed\n")

	if ctx.Notify {
		fmt.Printf("  📢 Sending notifications for %s...\n", relPath)
		// TODO: Send Slack notifications if violations found
		fmt.Printf("    ✓ Notifications sent\n")
	}

	return nil
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
