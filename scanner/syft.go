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
func (s *SyftScanner) GenerateSBOM(ctx context.Context, targetPath string, options *ScanOptions) (*models.SBOM, error) {
	if options == nil {
		options = DefaultScanOptions()
	}

	// Create output file in temp directory
	outputFile := filepath.Join(s.tempDir, fmt.Sprintf("sbom-%d.json", time.Now().Unix()))
	defer os.Remove(outputFile) // Clean up after processing

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
		return nil, fmt.Errorf("syft command failed: %w\nOutput: %s", err, string(output))
	}

	// Read the generated SBOM file
	sbomData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM file: %w", err)
	}

	// Parse Syft output
	var syftOutput models.SyftOutput
	if err := json.Unmarshal(sbomData, &syftOutput); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	// Process licenses for each artifact
	for i := range syftOutput.Artifacts {
		if err := syftOutput.Artifacts[i].UnmarshalLicenses(); err != nil {
			// Log error but continue processing
			fmt.Printf("Warning: failed to parse licenses for artifact %s: %v\n", syftOutput.Artifacts[i].Name, err)
		}
	}

	// Get Syft version
	syftVersion, err := s.GetVersion(ctx)
	if err != nil {
		syftVersion = "unknown"
	}

	// Convert to our SBOM model
	sbom := &models.SBOM{
		RepoName:       extractRepoName(targetPath),
		ModulePath:     extractModulePath(targetPath),
		ScanDate:       time.Now(),
		SyftVersion:    syftVersion,
		RawSBOM:        string(sbomData),
		ComponentCount: len(syftOutput.Artifacts),
	}

	return sbom, nil
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

// ParseSBOMToComponents converts Syft artifacts to our component models
func (s *SyftScanner) ParseSBOMToComponents(sbom *models.SBOM) ([]*models.Component, error) {
	var syftOutput models.SyftOutput
	if err := json.Unmarshal([]byte(sbom.RawSBOM), &syftOutput); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	// Process licenses for each artifact
	for i := range syftOutput.Artifacts {
		if err := syftOutput.Artifacts[i].UnmarshalLicenses(); err != nil {
			// Log error but continue processing
			fmt.Printf("Warning: failed to parse licenses for artifact %s: %v\n", syftOutput.Artifacts[i].Name, err)
		}
	}

	var components []*models.Component
	for _, artifact := range syftOutput.Artifacts {
		component := &models.Component{
			SBOMID:   sbom.ID,
			Name:     artifact.Name,
			Version:  artifact.Version,
			Type:     artifact.Type,
			PURL:     artifact.PURL,
			Language: artifact.Language,
			Licenses: artifact.Licenses,
			Metadata: artifact.Metadata,
		}

		// Set CPE if available
		if len(artifact.CPEs) > 0 {
			component.CPE = artifact.CPEs[0].CPE // Use first CPE's cpe field
		}

		// Convert locations
		for _, loc := range artifact.Locations {
			componentLoc := models.ComponentLocation{
				Path:      loc.Path,
				LayerID:   loc.LayerID,
				Namespace: loc.Namespace,
			}
			component.Locations = append(component.Locations, componentLoc)
		}

		components = append(components, component)
	}

	return components, nil
}

// ScanDirectory scans a directory and its subdirectories for package files
func (s *SyftScanner) ScanDirectory(ctx context.Context, dirPath string) ([]*models.SBOM, error) {
	var sboms []*models.SBOM

	// Look for package files that indicate separate modules
	packageFiles := map[string]string{
		"package.json":     "npm",
		"go.mod":           "go",
		"requirements.txt": "python",
		"Pipfile":          "python",
		"poetry.lock":      "python",
		"pom.xml":          "maven",
		"build.gradle":     "gradle",
		"build.gradle.kts": "gradle",
		"Cargo.toml":       "rust",
		"composer.json":    "php",
		"Gemfile":          "ruby",
		"mix.exs":          "elixir",
		"packages.config":  "nuget",
		"*.csproj":         "dotnet",
		// C++ package managers (modern C++)
		"conanfile.txt": "conan",
		"conanfile.py":  "conan",
		"vcpkg.json":    "vcpkg",
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking on errors
		}

		// Skip hidden directories and common build/cache directories
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") ||
				name == "node_modules" ||
				name == "vendor" ||
				name == "target" ||
				name == "build" ||
				name == "__pycache__" ||
				name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a package file
		fileName := info.Name()
		for packageFile, ecosystem := range packageFiles {
			if fileName == packageFile || (strings.Contains(packageFile, "*") &&
				strings.HasSuffix(fileName, strings.TrimPrefix(packageFile, "*"))) {

				// Generate SBOM for this module
				moduleDir := filepath.Dir(path)
				options := DefaultScanOptions()

				// Use specific catalogers based on ecosystem
				if catalogers := getCatalogersForEcosystem(ecosystem); len(catalogers) > 0 {
					options.Catalogers = catalogers
				}

				sbom, err := s.GenerateSBOM(ctx, moduleDir, options)
				if err != nil {
					// Log error but continue with other modules
					fmt.Printf("Warning: Failed to generate SBOM for %s: %v\n", moduleDir, err)
					return nil
				}

				sboms = append(sboms, sbom)
				return filepath.SkipDir // Don't scan subdirectories of this module
			}
		}

		// Check for C/C++ build files (additional logic for language detection)
		moduleDir := filepath.Dir(path)
		if ecosystem := DetermineEcosystemFromBuildFiles(moduleDir); ecosystem != "" {
			// Check if we already processed this directory
			for _, existingSbom := range sboms {
				if existingSbom.ModulePath == moduleDir {
					return nil // Already processed
				}
			}

			options := DefaultScanOptions()
			if catalogers := getCatalogersForEcosystem(ecosystem); len(catalogers) > 0 {
				options.Catalogers = catalogers
			}

			sbom, err := s.GenerateSBOM(ctx, moduleDir, options)
			if err != nil {
				fmt.Printf("Warning: Failed to generate SBOM for C/C++ module %s: %v\n", moduleDir, err)
				return nil
			}

			sboms = append(sboms, sbom)
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %w", err)
	}

	// If no modules found, scan the entire directory
	if len(sboms) == 0 {
		sbom, err := s.GenerateSBOM(ctx, dirPath, DefaultScanOptions())
		if err != nil {
			return nil, fmt.Errorf("failed to generate SBOM for directory: %w", err)
		}
		sboms = append(sboms, sbom)
	}

	return sboms, nil
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

// Helper functions

func extractRepoName(path string) string {
	// Extract repository name from path
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Base(path)
	}

	// Look for .git directory to determine repo root
	current := abs
	for {
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			return filepath.Base(current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return filepath.Base(abs)
}

func extractModulePath(path string) string {
	// Extract module path relative to repository root
	abs, err := filepath.Abs(path)
	if err != nil {
		return "."
	}

	// Look for .git directory to determine repo root
	current := abs
	repoRoot := ""
	for {
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			repoRoot = current
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	if repoRoot == "" {
		return "."
	}

	relPath, err := filepath.Rel(repoRoot, abs)
	if err != nil {
		return "."
	}

	if relPath == "." {
		return "root"
	}

	return relPath
}

func getCatalogersForEcosystem(ecosystem string) []string {
	catalogers := map[string][]string{
		"npm":    {"javascript-package"},
		"go":     {"go-module"},
		"python": {"python-package"},
		"maven":  {"java-pom"},
		"gradle": {"java-gradle"},
		"rust":   {"rust-cargo"},
		"php":    {"php-composer"},
		"ruby":   {"ruby-gemfile"},
		"elixir": {"elixir-mix"},
		"nuget":  {"dotnet-deps"},
		"dotnet": {"dotnet-deps"},
		// C++ package managers (modern C++)
		"conan":     {"conan-lock", "conan"},
		"vcpkg":     {"vcpkg"},
		"cmake-cpp": {"cmake"},
		"bazel-cpp": {"c-cataloger"},
		"meson-cpp": {"c-cataloger"},
		// C language build systems (traditional C)
		"make-c":      {"c-cataloger"},
		"autotools-c": {"c-cataloger"},
		"scons-c":     {"c-cataloger"},
	}

	return catalogers[ecosystem]
}

// DetectLanguageFromDirectory analyzes directory contents to detect C vs C++
func DetectLanguageFromDirectory(dirPath string) string {
	cppExtensions := []string{".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"}
	cExtensions := []string{".c", ".h"}

	var cppFiles, cFiles int

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		for _, cppExt := range cppExtensions {
			if ext == cppExt {
				cppFiles++
				return nil
			}
		}
		for _, cExt := range cExtensions {
			if ext == cExt {
				cFiles++
				return nil
			}
		}
		return nil
	})

	if err != nil {
		return "unknown"
	}

	// If we have C++ files, it's C++
	if cppFiles > 0 {
		return "cpp"
	}

	// If we only have C files, it's C
	if cFiles > 0 {
		return "c"
	}

	return "unknown"
}

// DetermineEcosystemFromBuildFiles determines ecosystem based on build files and source code
func DetermineEcosystemFromBuildFiles(dirPath string) string {
	buildFiles := map[string]string{
		// C++ specific (modern package managers)
		"conanfile.txt": "conan",
		"conanfile.py":  "conan",
		"vcpkg.json":    "vcpkg",
		// Build systems that could be C or C++
		"CMakeLists.txt": "cmake",
		"Makefile":       "make",
		"BUILD":          "bazel",
		"BUILD.bazel":    "bazel",
		"meson.build":    "meson",
		"configure.ac":   "autotools",
		"configure.in":   "autotools",
		"SConstruct":     "scons",
	}

	for file, ecosystem := range buildFiles {
		if _, err := os.Stat(filepath.Join(dirPath, file)); err == nil {
			// For build systems that could be C or C++, detect language
			if ecosystem == "cmake" || ecosystem == "make" || ecosystem == "bazel" ||
				ecosystem == "meson" || ecosystem == "autotools" || ecosystem == "scons" {
				lang := DetectLanguageFromDirectory(dirPath)
				if lang == "cpp" {
					return ecosystem + "-cpp"
				} else if lang == "c" {
					return ecosystem + "-c"
				}
				// Default to C++ for ambiguous cases with modern build systems
				return ecosystem + "-cpp"
			}
			return ecosystem
		}
	}

	return ""
}
