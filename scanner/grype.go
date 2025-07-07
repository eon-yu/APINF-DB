package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"oss-compliance-scanner/models"
)

// GrypeScanner handles vulnerability scanning using Grype
type GrypeScanner struct {
	grypePath string
	tempDir   string
	cacheDir  string
	timeout   time.Duration
}

// NewGrypeScanner creates a new Grype scanner instance
func NewGrypeScanner(grypePath, tempDir, cacheDir string, timeoutSeconds int) *GrypeScanner {
	return &GrypeScanner{
		grypePath: grypePath,
		tempDir:   tempDir,
		cacheDir:  cacheDir,
		timeout:   time.Duration(timeoutSeconds) * time.Second,
	}
}

// VulnScanOptions represents options for vulnerability scanning
type VulnScanOptions struct {
	OutputFormat string   // json, table, cyclonedx, sarif
	Scope        string   // squashed, all-layers, directory
	Platform     string   // linux/amd64, darwin/amd64, etc.
	FailOn       string   // negligible, low, medium, high, critical
	OnlyFixed    bool     // only show vulnerabilities with fixes
	IgnoreStates []string // ignore vulnerabilities in these states
	Quiet        bool
	Verbose      bool
}

// DefaultVulnScanOptions returns default vulnerability scan options
func DefaultVulnScanOptions() *VulnScanOptions {
	return &VulnScanOptions{
		OutputFormat: "json",
		Scope:        "squashed",
		Platform:     "",
		FailOn:       "",
		OnlyFixed:    false,
		IgnoreStates: nil,
		Quiet:        false,
		Verbose:      false,
	}
}

// ScanVulnerabilities scans for vulnerabilities in the given target
func (g *GrypeScanner) ScanVulnerabilities(ctx context.Context, target string, options *VulnScanOptions) ([]*models.Vulnerability, error) {
	if options == nil {
		options = DefaultVulnScanOptions()
	}

	// Create output file in temp directory
	outputFile := filepath.Join(g.tempDir, fmt.Sprintf("vuln-%d.json", time.Now().Unix()))
	defer os.Remove(outputFile) // Clean up after processing

	// Build Grype command
	args := []string{
		target,
		"-o", fmt.Sprintf("%s=%s", options.OutputFormat, outputFile),
	}

	// Add optional parameters
	if options.Scope != "" {
		args = append(args, "--scope", options.Scope)
	}
	if options.Platform != "" {
		args = append(args, "--platform", options.Platform)
	}
	if options.FailOn != "" {
		args = append(args, "--fail-on", options.FailOn)
	}
	if options.OnlyFixed {
		args = append(args, "--only-fixed")
	}
	if len(options.IgnoreStates) > 0 {
		for _, state := range options.IgnoreStates {
			args = append(args, "--ignore-states", state)
		}
	}
	if options.Quiet {
		args = append(args, "--quiet")
	}
	if options.Verbose {
		args = append(args, "--verbose")
	}

	// Set cache directory if specified
	if g.cacheDir != "" {
		args = append(args, "--cache-dir", g.cacheDir)
	}

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, g.grypePath, args...)

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Grype returns non-zero exit code when vulnerabilities are found
		// Check if it's a real error or just vulnerabilities found
		if !strings.Contains(string(output), "found vulnerabilities") {
			return nil, fmt.Errorf("grype command failed: %w\nOutput: %s", err, string(output))
		}
	}

	// Read the generated vulnerability report
	vulnData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vulnerability file: %w", err)
	}

	// Parse Grype output
	var grypeOutput models.GrypeOutput
	if err := json.Unmarshal(vulnData, &grypeOutput); err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability JSON: %w", err)
	}

	// Convert to our vulnerability models
	vulnerabilities, err := g.parseGrypeMatches(grypeOutput.Matches)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grype matches: %w", err)
	}

	return vulnerabilities, nil
}

// ScanSBOM scans for vulnerabilities using an existing SBOM
func (g *GrypeScanner) ScanSBOM(ctx context.Context, sbomPath string, options *VulnScanOptions) ([]*models.Vulnerability, error) {
	return g.ScanVulnerabilities(ctx, fmt.Sprintf("sbom:%s", sbomPath), options)
}

// ScanDirectory scans a directory for vulnerabilities
func (g *GrypeScanner) ScanDirectory(ctx context.Context, dirPath string, options *VulnScanOptions) ([]*models.Vulnerability, error) {
	return g.ScanVulnerabilities(ctx, fmt.Sprintf("dir:%s", dirPath), options)
}

// ScanImage scans a container image for vulnerabilities
func (g *GrypeScanner) ScanImage(ctx context.Context, imageName string, options *VulnScanOptions) ([]*models.Vulnerability, error) {
	return g.ScanVulnerabilities(ctx, imageName, options)
}

// GetVersion gets the Grype version
func (g *GrypeScanner) GetVersion(ctx context.Context) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, g.grypePath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get grype version: %w", err)
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "grype") || strings.HasPrefix(line, "Application:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[len(parts)-1]), nil
			}
		}
	}

	return strings.TrimSpace(string(output)), nil
}

// UpdateDatabase updates the Grype vulnerability database
func (g *GrypeScanner) UpdateDatabase(ctx context.Context) error {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Minute) // Longer timeout for DB update
	defer cancel()

	args := []string{"db", "update"}
	if g.cacheDir != "" {
		args = append(args, "--cache-dir", g.cacheDir)
	}

	cmd := exec.CommandContext(cmdCtx, g.grypePath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update grype database: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// GetDatabaseInfo gets information about the vulnerability database
func (g *GrypeScanner) GetDatabaseInfo(ctx context.Context) (map[string]interface{}, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := []string{"db", "status"}
	if g.cacheDir != "" {
		args = append(args, "--cache-dir", g.cacheDir)
	}

	cmd := exec.CommandContext(cmdCtx, g.grypePath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get grype database info: %w", err)
	}

	// Parse the output (usually in a structured format)
	info := make(map[string]interface{})
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			info[key] = value
		}
	}

	return info, nil
}

// ValidateInstallation checks if Grype is properly installed
func (g *GrypeScanner) ValidateInstallation(ctx context.Context) error {
	// Check if Grype executable exists
	if filepath.IsAbs(g.grypePath) {
		if _, err := os.Stat(g.grypePath); err != nil {
			return fmt.Errorf("grype not found at %s: %w", g.grypePath, err)
		}
	} else {
		if _, err := exec.LookPath(g.grypePath); err != nil {
			return fmt.Errorf("grype not found in PATH: %w", err)
		}
	}

	// Test basic functionality
	_, err := g.GetVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get grype version: %w", err)
	}

	// Check database status
	_, err = g.GetDatabaseInfo(ctx)
	if err != nil {
		return fmt.Errorf("grype database not available: %w", err)
	}

	return nil
}

// parseGrypeMatches converts Grype matches to our vulnerability models
func (g *GrypeScanner) parseGrypeMatches(matches []models.GrypeMatch) ([]*models.Vulnerability, error) {
	var vulnerabilities []*models.Vulnerability

	for _, match := range matches {
		vuln := &models.Vulnerability{
			VulnID:      match.Vulnerability.ID,
			Severity:    match.Vulnerability.Severity,
			Description: match.Vulnerability.Description,
			URLs:        match.Vulnerability.URLs,
		}

		// Parse CVSS scores
		for _, cvss := range match.Vulnerability.Cvss {
			if cvss.Version == "3.0" || cvss.Version == "3.1" {
				vuln.CVSS3Score = cvss.Metrics.BaseScore
			} else if cvss.Version == "2.0" {
				vuln.CVSS2Score = cvss.Metrics.BaseScore
			}
		}

		// Parse published and modified dates
		if match.Vulnerability.PublishedDate != "" {
			if pubDate, err := time.Parse(time.RFC3339, match.Vulnerability.PublishedDate); err == nil {
				vuln.PublishedDate = &pubDate
			}
		}
		if match.Vulnerability.ModifiedDate != "" {
			if modDate, err := time.Parse(time.RFC3339, match.Vulnerability.ModifiedDate); err == nil {
				vuln.ModifiedDate = &modDate
			}
		}

		// Parse fix information
		if len(match.Vulnerability.Fix.Versions) > 0 {
			for _, version := range match.Vulnerability.Fix.Versions {
				fix := models.VulnerabilityFix{
					Version: version,
					State:   match.Vulnerability.Fix.State,
				}
				vuln.Fixes = append(vuln.Fixes, fix)
			}
		}

		// Set metadata
		vuln.Metadata = map[string]interface{}{
			"data_source":   match.Vulnerability.DataSource,
			"namespace":     match.Vulnerability.Namespace,
			"advisories":    match.Vulnerability.Advisories,
			"artifact":      match.Artifact,
			"match_details": match.MatchDetails,
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// FilterVulnerabilities filters vulnerabilities based on severity and other criteria
func (g *GrypeScanner) FilterVulnerabilities(vulnerabilities []*models.Vulnerability, minSeverity models.SeverityLevel, onlyFixed bool) []*models.Vulnerability {
	var filtered []*models.Vulnerability

	for _, vuln := range vulnerabilities {
		severity := models.ParseSeverity(vuln.Severity)

		// Check severity threshold
		if severity < minSeverity {
			continue
		}

		// Check if only fixed vulnerabilities are requested
		if onlyFixed && len(vuln.Fixes) == 0 {
			continue
		}

		filtered = append(filtered, vuln)
	}

	return filtered
}

// GroupVulnerabilitiesBySeverity groups vulnerabilities by severity level
func (g *GrypeScanner) GroupVulnerabilitiesBySeverity(vulnerabilities []*models.Vulnerability) map[string][]*models.Vulnerability {
	groups := make(map[string][]*models.Vulnerability)

	for _, vuln := range vulnerabilities {
		severity := vuln.Severity
		if severity == "" {
			severity = "Unknown"
		}
		groups[severity] = append(groups[severity], vuln)
	}

	return groups
}

// CountVulnerabilitiesBySeverity counts vulnerabilities by severity level
func (g *GrypeScanner) CountVulnerabilitiesBySeverity(vulnerabilities []*models.Vulnerability) map[string]int {
	counts := map[string]int{
		"Critical": 0,
		"High":     0,
		"Medium":   0,
		"Low":      0,
		"Unknown":  0,
	}

	for _, vuln := range vulnerabilities {
		severity := vuln.Severity
		if severity == "" {
			severity = "Unknown"
		}
		counts[severity]++
	}

	return counts
}
