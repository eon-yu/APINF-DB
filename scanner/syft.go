package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// SyftScanner handles Syft SBOM generation
type SyftScanner struct {
	syftPath string
	tempDir  string
	cacheDir string
	timeout  time.Duration
}

// NewSyftScanner creates a new Syft scanner instance
func NewSyftScanner(syftPath, tempDir, cacheDir string, timeoutSeconds int) *SyftScanner {
	return &SyftScanner{
		syftPath: syftPath,
		tempDir:  tempDir,
		cacheDir: cacheDir,
		timeout:  time.Duration(timeoutSeconds) * time.Second,
	}
}

// ScanOptions represents options for SBOM generation
type ScanOptions struct {
	OutputFormat string   // json, spdx-json, cyclonedx-json, table
	Scope        string   // squashed, all-layers, directory
	Platform     string   // linux/amd64, darwin/amd64, etc.
	Catalogers   []string // specific catalogers to use
	Quiet        bool
	Verbose      bool
}

// DefaultScanOptions returns default scan options
func DefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		OutputFormat: "json",
		Scope:        "squashed",
		Platform:     "",
		Catalogers:   nil,
		Quiet:        false,
		Verbose:      false,
	}
}

// GenerateSBOM generates an SBOM for the given target path
func (s *SyftScanner) GenerateSBOM(ctx context.Context, targetPath string) error {
	options := DefaultScanOptions()

	// Create output file in temp directory
	fileName := fmt.Sprintf("sbom-%d.json", time.Now().Unix())
	outputFile := filepath.Join(s.tempDir, fileName)
	mvPath := path.Join(s.tempDir, "syft")
	os.MkdirAll(mvPath, 0755)
	defer os.Rename(outputFile, path.Join(mvPath, fileName)) // Clean up after processing

	// Build Syft command
	args := []string{
		"scan",
		targetPath,
		"-o", fmt.Sprintf("%s=%s", options.OutputFormat, outputFile),
	}

	// Add optional parameters
	if options.Scope != "" {
		args = append(args, "--scope", options.Scope)
	}
	if options.Platform != "" {
		args = append(args, "--platform", options.Platform)
	}
	if len(options.Catalogers) > 0 {
		args = append(args, "--select-catalogers", strings.Join(options.Catalogers, ","))
	}
	if options.Quiet {
		args = append(args, "--quiet")
	}
	if options.Verbose {
		args = append(args, "--verbose")
	}

	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, s.syftPath, args...)
	cmd.Dir = targetPath

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("syft command failed: %w\nOutput: %s", err, string(output))
	}

	// Read the generated SBOM file
	_, err = os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("failed to read SBOM file: %w", err)
	}

	return nil
}

// GetVersion gets the Syft version
func (s *SyftScanner) GetVersion(ctx context.Context) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, s.syftPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get syft version: %w", err)
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "syft") || strings.HasPrefix(line, "Application:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[len(parts)-1]), nil
			}
		}
	}

	return strings.TrimSpace(string(output)), nil
}

// ValidateInstallation checks if Syft is properly installed
func (s *SyftScanner) ValidateInstallation(ctx context.Context) error {
	// Check if Syft executable exists
	if filepath.IsAbs(s.syftPath) {
		if _, err := os.Stat(s.syftPath); err != nil {
			return fmt.Errorf("syft not found at %s: %w", s.syftPath, err)
		}
	} else {
		if _, err := exec.LookPath(s.syftPath); err != nil {
			return fmt.Errorf("syft not found in PATH: %w", err)
		}
	}

	// Test basic functionality
	_, err := s.GetVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get syft version: %w", err)
	}

	return nil
}
