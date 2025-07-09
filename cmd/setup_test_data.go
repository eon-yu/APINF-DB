package cmd

import (
	"fmt"
	"log"
	"time"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"

	"github.com/spf13/cobra"
)

var setupTestDataCmd = &cobra.Command{
	Use:   "setup-test-data",
	Short: "Setup test data for repository management",
	Long:  "Creates sample repositories, SBOMs, components, and vulnerabilities for testing repository management features",
	Run: func(cmd *cobra.Command, args []string) {
		dbPath, _ := cmd.Flags().GetString("db-path")

		if dbPath == "" {
			dbPath = "./oss-compliance.db"
		}

		database, err := db.NewDatabase("sqlite3", dbPath)
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer database.Close()

		// Run migrations first
		if err := database.RunMigrations(); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}

		// Create test data
		if err := createRepositoryTestData(database); err != nil {
			log.Fatalf("Failed to create test data: %v", err)
		}

		fmt.Println("✅ Test data created successfully!")
		fmt.Println("You can now access the web interface to see the repository management features.")
	},
}

func init() {
	rootCmd.AddCommand(setupTestDataCmd)
	setupTestDataCmd.Flags().String("db-path", "", "Path to SQLite database file")
}

func createRepositoryTestData(database *db.Database) error {
	fmt.Println("Creating test repositories and SBOMs...")

	// Test repositories with different module structures
	repositories := []struct {
		RepoName    string
		ModulePaths []string
		Description string
	}{
		{
			"frontend-webapp",
			[]string{".", "packages/ui", "packages/core", "packages/utils"},
			"React-based frontend application with multiple packages",
		},
		{
			"backend-api",
			[]string{"."},
			"Node.js REST API service",
		},
		{
			"microservices-platform",
			[]string{"api-gateway", "user-service", "notification-service", "payment-service", "analytics-service"},
			"Microservices platform with multiple services",
		},
		{
			"mobile-app",
			[]string{".", "shared/components", "shared/utils"},
			"React Native mobile application",
		},
		{
			"data-pipeline",
			[]string{"etl", "processors", "transformers"},
			"Data processing pipeline with multiple modules",
		},
	}

	for _, repo := range repositories {
		fmt.Printf("  Creating repository: %s (%d modules)\n", repo.RepoName, len(repo.ModulePaths))

		for i, modulePath := range repo.ModulePaths {
			// Create SBOM with varying scan dates
			scanDate := time.Now().Add(-time.Duration(len(repo.ModulePaths)-i) * time.Hour * 24)
			componentCount := 20 + i*10 + (len(repo.RepoName)%5)*5

			sbom := &models.SBOM{
				RepoName:       repo.RepoName,
				ModulePath:     modulePath,
				ScanDate:       scanDate,
				SyftVersion:    "v0.95.0",
				RawSBOM:        fmt.Sprintf(`{"name": "%s/%s", "components": [], "description": "%s"}`, repo.RepoName, modulePath, repo.Description),
				ComponentCount: componentCount,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}

			if err := database.CreateSBOM(sbom); err != nil {
				return fmt.Errorf("failed to create SBOM for %s/%s: %w", repo.RepoName, modulePath, err)
			}

			// Get the created SBOM to get its ID
			sboms, err := database.GetAllSBOMs(1000)
			if err != nil {
				return fmt.Errorf("failed to get SBOMs: %w", err)
			}

			var createdSBOM *models.SBOM
			for _, s := range sboms {
				if s.RepoName == repo.RepoName && s.ModulePath == modulePath {
					createdSBOM = s
					break
				}
			}

			if createdSBOM == nil {
				return fmt.Errorf("failed to find created SBOM")
			}

			// Create components for this SBOM
			if err := createTestComponents(database, createdSBOM, componentCount); err != nil {
				return fmt.Errorf("failed to create components for %s/%s: %w", repo.RepoName, modulePath, err)
			}
		}
	}

	fmt.Printf("✅ Created %d repositories with various module structures\n", len(repositories))
	return nil
}

func createTestComponents(database *db.Database, sbom *models.SBOM, componentCount int) error {
	// Different types of components based on repository type
	var componentTypes []componentTemplate

	switch {
	case contains(sbom.RepoName, "frontend") || contains(sbom.RepoName, "mobile"):
		componentTypes = []componentTemplate{
			{"react", "18.2.0", "library", "javascript", []string{"MIT"}},
			{"typescript", "4.9.5", "library", "typescript", []string{"Apache-2.0"}},
			{"webpack", "5.75.0", "tool", "javascript", []string{"MIT"}},
			{"eslint", "8.33.0", "tool", "javascript", []string{"MIT"}},
			{"@types/node", "18.11.18", "library", "typescript", []string{"MIT"}},
		}
	case contains(sbom.RepoName, "backend") || contains(sbom.RepoName, "api"):
		componentTypes = []componentTemplate{
			{"express", "4.18.2", "library", "javascript", []string{"MIT"}},
			{"mongoose", "6.8.4", "library", "javascript", []string{"MIT"}},
			{"jsonwebtoken", "9.0.0", "library", "javascript", []string{"MIT"}},
			{"bcrypt", "5.1.0", "library", "javascript", []string{"MIT"}},
			{"cors", "2.8.5", "library", "javascript", []string{"MIT"}},
		}
	case contains(sbom.RepoName, "microservice"):
		componentTypes = []componentTemplate{
			{"spring-boot", "2.7.8", "framework", "java", []string{"Apache-2.0"}},
			{"spring-cloud", "2021.0.5", "library", "java", []string{"Apache-2.0"}},
			{"spring-data-jpa", "2.7.7", "library", "java", []string{"Apache-2.0"}},
			{"postgresql", "42.5.1", "library", "java", []string{"BSD-2-Clause"}},
			{"redis", "4.4.6", "library", "java", []string{"BSD-3-Clause"}},
		}
	default:
		componentTypes = []componentTemplate{
			{"lodash", "4.17.21", "library", "javascript", []string{"MIT"}},
			{"axios", "1.2.6", "library", "javascript", []string{"MIT"}},
			{"moment", "2.29.4", "library", "javascript", []string{"MIT"}},
			{"uuid", "9.0.0", "library", "javascript", []string{"MIT"}},
			{"crypto-js", "4.1.1", "library", "javascript", []string{"MIT"}},
		}
	}

	for i := 0; i < componentCount; i++ {
		template := componentTypes[i%len(componentTypes)]

		// Make component names unique by adding index
		componentName := fmt.Sprintf("%s-%d", template.Name, i+1)
		componentVersion := fmt.Sprintf("%s.%d", template.Version, i+1)

		component := &models.Component{
			SBOMID:        sbom.ID,
			Name:          componentName,
			Version:       componentVersion,
			Type:          template.Type,
			PURL:          fmt.Sprintf("pkg:%s/%s@%s", template.Language, componentName, componentVersion),
			Language:      template.Language,
			LicensesJSON:  fmt.Sprintf(`["%s"]`, template.Licenses[0]),
			LocationsJSON: fmt.Sprintf(`[{"path": "/node_modules/%s"}]`, componentName),
			MetadataJSON:  `{}`,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := database.CreateComponent(component); err != nil {
			return fmt.Errorf("failed to create component %s: %w", component.Name, err)
		}

		// Create vulnerabilities for some components (every 4th component)
		if (i+1)%4 == 0 {
			if err := createTestVulnerability(database, sbom.ID, componentName, i); err != nil {
				return fmt.Errorf("failed to create vulnerability for component %s: %w", componentName, err)
			}
		}
	}

	return nil
}

type componentTemplate struct {
	Name     string
	Version  string
	Type     string
	Language string
	Licenses []string
}

func createTestVulnerability(database *db.Database, sbomID int, componentName string, index int) error {
	// Get components for this SBOM to find the component ID
	components, err := database.GetComponentsBySBOM(sbomID)
	if err != nil {
		return err
	}

	var targetComponent *models.Component
	for _, comp := range components {
		if comp.Name == componentName {
			targetComponent = comp
			break
		}
	}

	if targetComponent == nil {
		return fmt.Errorf("component %s not found", componentName)
	}

	severities := []string{"Low", "Medium", "High", "Critical"}
	severity := severities[index%len(severities)]

	publishedDate := time.Now().Add(-time.Duration(index) * time.Hour * 24)
	modifiedDate := time.Now()

	vuln := &models.Vulnerability{
		ComponentID:   targetComponent.ID,
		VulnID:        fmt.Sprintf("CVE-2023-%04d", 1000+index),
		Severity:      severity,
		CVSS3Score:    float64(4 + (index % 6)),
		CVSS2Score:    float64(3 + (index % 5)),
		Description:   fmt.Sprintf("Test vulnerability in %s - %s severity issue", componentName, severity),
		PublishedDate: &publishedDate,
		ModifiedDate:  &modifiedDate,
		URLs:          []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-2023-%04d", 1000+index)},
		Fixes:         []models.VulnerabilityFix{{Version: "999.0.0", State: "fixed"}},
		Metadata:      map[string]any{},
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Marshal fields for database storage
	if err := vuln.MarshalVulnerabilityFields(); err != nil {
		return err
	}

	return database.CreateVulnerability(vuln)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()
}
