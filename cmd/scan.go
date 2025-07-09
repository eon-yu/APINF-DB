package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"oss-compliance-scanner/util"

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
	scanCtx := &util.ScanContext{
		RepoPath:   absRepoPath,
		ModulePath: modulePath,
		SkipSBOM:   skipSBOM,
		SkipVuln:   skipVuln,
		Notify:     notify,
		Verbose:    verbose,
	}

	// Execute scan
	if err := util.ExecuteScan(scanCtx); err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Println("✅ Scan completed successfully!")
}
