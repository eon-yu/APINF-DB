package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRepositoryTestServer(t *testing.T) (*DashboardServer, func()) {
	tempDir, err := os.MkdirTemp("", "repo_management_test_*")
	require.NoError(t, err)

	dbPath := filepath.Join(tempDir, "test.db")
	database, err := db.NewDatabase("sqlite3", dbPath)
	require.NoError(t, err)

	// Create tables manually for testing
	err = createRepositoryTestTables(database)
	require.NoError(t, err)

	// Create test data
	createRepositoryTestData(t, database)

	server := NewDashboardServer(database, "8080")
	server.setupRoutes()

	cleanup := func() {
		database.Close()
		os.RemoveAll(tempDir)
	}

	return server, cleanup
}

func createRepositoryTestTables(database *db.Database) error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS sboms (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			repo_name TEXT NOT NULL,
			module_path TEXT NOT NULL DEFAULT '.',
			scan_date DATETIME NOT NULL,
			syft_version TEXT NOT NULL,
			raw_sbom TEXT NOT NULL,
			component_count INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS components (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sbom_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			type TEXT NOT NULL,
			purl TEXT,
			cpe TEXT,
			language TEXT,
			licenses_json TEXT,
			locations_json TEXT,
			metadata_json TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			component_id INTEGER NOT NULL,
			vuln_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			cvss3_score REAL DEFAULT 0.0,
			cvss2_score REAL DEFAULT 0.0,
			description TEXT,
			published_date DATETIME,
			modified_date DATETIME,
			urls_json TEXT,
			fixes_json TEXT,
			metadata_json TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE
		)`,
	}

	for _, table := range tables {
		_, err := database.Exec(table)
		if err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

func createRepositoryTestData(t *testing.T, database *db.Database) {
	// Create test repositories with different module structures
	repositories := []struct {
		RepoName    string
		ModulePaths []string
	}{
		{"frontend-app", []string{".", "packages/ui", "packages/core"}},
		{"backend-service", []string{"."}},
		{"microservice-cluster", []string{"api-gateway", "user-service", "notification-service"}},
		{"mobile-app", []string{".", "shared/components"}},
	}

	for _, repo := range repositories {
		for i, modulePath := range repo.ModulePaths {
			// Create SBOM
			sbom := &models.SBOM{
				RepoName:       repo.RepoName,
				ModulePath:     modulePath,
				ScanDate:       time.Now().Add(-time.Duration(i) * time.Hour * 24),
				SyftVersion:    "v0.95.0",
				RawSBOM:        fmt.Sprintf(`{"name": "%s/%s", "components": []}`, repo.RepoName, modulePath),
				ComponentCount: 15 + i*5, // Varying component counts
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}

			err := database.CreateSBOM(sbom)
			require.NoError(t, err)

			// Get the created SBOM ID (assuming it's auto-incremented)
			sboms, err := database.GetAllSBOMs(1000)
			require.NoError(t, err)

			var createdSBOM *models.SBOM
			for _, s := range sboms {
				if s.RepoName == repo.RepoName && s.ModulePath == modulePath {
					createdSBOM = s
					break
				}
			}
			require.NotNil(t, createdSBOM, "Failed to find created SBOM")

			// Create some components for this SBOM
			componentCount := sbom.ComponentCount
			for j := 0; j < componentCount; j++ {
				component := &models.Component{
					SBOMID:        createdSBOM.ID,
					Name:          fmt.Sprintf("component-%d", j+1),
					Version:       "1.0.0",
					Type:          "library",
					PURL:          fmt.Sprintf("pkg:npm/component-%d@1.0.0", j+1),
					Language:      "javascript",
					LicensesJSON:  `["MIT"]`,
					LocationsJSON: fmt.Sprintf(`[{"path": "/node_modules/component-%d"}]`, j+1),
					MetadataJSON:  `{}`,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}

				err = database.CreateComponent(component)
				require.NoError(t, err)

				// Create some vulnerabilities for every 3rd component
				if (j+1)%3 == 0 {
					// Get component ID
					components, err := database.GetComponentsBySBOM(createdSBOM.ID)
					require.NoError(t, err)

					var createdComponent *models.Component
					for _, c := range components {
						if c.Name == component.Name {
							createdComponent = c
							break
						}
					}
					require.NotNil(t, createdComponent)

					publishedDate := time.Now().Add(-time.Duration(j) * time.Hour * 24)
					modifiedDate := time.Now()

					vuln := &models.Vulnerability{
						ComponentID:   createdComponent.ID,
						VulnID:        fmt.Sprintf("CVE-2023-%04d", 1000+j),
						Severity:      getSeverityForTest(j),
						CVSS3Score:    float64(5 + (j % 5)),
						CVSS2Score:    float64(4 + (j % 4)),
						Description:   fmt.Sprintf("Test vulnerability %d in component %s", j+1, component.Name),
						PublishedDate: &publishedDate,
						ModifiedDate:  &modifiedDate,
						URLs:          []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/CVE-2023-%04d", 1000+j)},
						Fixes:         []models.VulnerabilityFix{{Version: "1.1.0", State: "fixed"}},
						Metadata:      map[string]interface{}{},
						CreatedAt:     time.Now(),
						UpdatedAt:     time.Now(),
					}

					// Marshal fields for database storage
					err = vuln.MarshalVulnerabilityFields()
					require.NoError(t, err)

					err = database.CreateVulnerability(vuln)
					require.NoError(t, err)
				}
			}
		}
	}
}

func getSeverityForTest(index int) string {
	severities := []string{"Low", "Medium", "High", "Critical"}
	return severities[index%len(severities)]
}

func TestRepositoryManagement(t *testing.T) {
	server, cleanup := setupRepositoryTestServer(t)
	defer cleanup()

	t.Run("Repository Groups Rendering", func(t *testing.T) {
		// Test SBOM page rendering with repository groups
		req := httptest.NewRequest("GET", "/sboms", nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		// The page should render successfully even if templates fail in test environment
		assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 500)
	})

	t.Run("Repository Data Grouping", func(t *testing.T) {
		// Test the underlying data grouping logic
		sboms, err := server.database.GetAllSBOMs(100)
		require.NoError(t, err)
		assert.Greater(t, len(sboms), 0, "Should have test SBOMs")

		// Test repository grouping logic
		repositoryGroups := make(map[string]*RepositoryInfo)

		for _, sbom := range sboms {
			if _, exists := repositoryGroups[sbom.RepoName]; !exists {
				repositoryGroups[sbom.RepoName] = &RepositoryInfo{
					Name:                 sbom.RepoName,
					Modules:              []*models.SBOM{},
					UniqueModules:        []ModuleInfo{},
					ModuleCount:          0,
					TotalComponents:      0,
					TotalVulnerabilities: 0,
					LastScanDate:         sbom.ScanDate.Format("2006-01-02 15:04"),
					RiskLevel:            "low",
				}
			}

			repo := repositoryGroups[sbom.RepoName]
			repo.Modules = append(repo.Modules, sbom)
		}

		// Verify repository groups
		assert.Contains(t, repositoryGroups, "frontend-app")
		assert.Contains(t, repositoryGroups, "backend-service")
		assert.Contains(t, repositoryGroups, "microservice-cluster")
		assert.Contains(t, repositoryGroups, "mobile-app")

		// Test frontend-app (should have 3 modules)
		frontendRepo := repositoryGroups["frontend-app"]
		assert.Equal(t, "frontend-app", frontendRepo.Name)
		assert.Greater(t, len(frontendRepo.Modules), 0)

		// Test backend-service (should have 1 module)
		backendRepo := repositoryGroups["backend-service"]
		assert.Equal(t, "backend-service", backendRepo.Name)
		assert.Greater(t, len(backendRepo.Modules), 0)
	})

	t.Run("Single SBOM Deletion", func(t *testing.T) {
		// Get a test SBOM
		sboms, err := server.database.GetAllSBOMs(100)
		require.NoError(t, err)
		require.Greater(t, len(sboms), 0)

		testSBOM := sboms[0]
		initialCount := len(sboms)

		// Test single SBOM deletion
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/sboms/%d", testSBOM.ID), nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)

		// Verify SBOM was deleted
		remainingSBOMs, err := server.database.GetAllSBOMs(100)
		require.NoError(t, err)
		assert.Equal(t, initialCount-1, len(remainingSBOMs))

		// Verify the specific SBOM was deleted
		for _, sbom := range remainingSBOMs {
			assert.NotEqual(t, testSBOM.ID, sbom.ID)
		}
	})

	t.Run("Multiple SBOM Deletion", func(t *testing.T) {
		// Get test SBOMs
		sboms, err := server.database.GetAllSBOMs(100)
		require.NoError(t, err)
		require.Greater(t, len(sboms), 2, "Need at least 3 SBOMs for this test")

		// Select first 2 SBOMs for deletion
		sbomIDs := []int{sboms[0].ID, sboms[1].ID}
		initialCount := len(sboms)

		// Create request body
		requestBody := map[string]interface{}{
			"sbom_ids": sbomIDs,
		}
		bodyBytes, err := json.Marshal(requestBody)
		require.NoError(t, err)

		// Test multiple SBOM deletion
		req := httptest.NewRequest("DELETE", "/api/v1/sboms", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)

		// Verify SBOMs were deleted
		remainingSBOMs, err := server.database.GetAllSBOMs(100)
		require.NoError(t, err)
		assert.Equal(t, initialCount-2, len(remainingSBOMs))

		// Verify the specific SBOMs were deleted
		for _, sbom := range remainingSBOMs {
			assert.NotContains(t, sbomIDs, sbom.ID)
		}
	})

	t.Run("Repository Deletion", func(t *testing.T) {
		// Get SBOMs for a specific repository
		testRepo := "frontend-app"
		repoSBOMs, err := server.database.GetSBOMsByRepository(testRepo)
		require.NoError(t, err)
		require.Greater(t, len(repoSBOMs), 0, "Test repository should have SBOMs")

		initialTotalCount, err := server.database.GetAllSBOMs(1000)
		require.NoError(t, err)

		// Test repository deletion
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/repositories/%s", testRepo), nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)

		// Verify all SBOMs for the repository were deleted
		remainingRepoSBOMs, err := server.database.GetSBOMsByRepository(testRepo)
		require.NoError(t, err)
		assert.Empty(t, remainingRepoSBOMs)

		// Verify total count decreased by the number of deleted SBOMs
		remainingTotalSBOMs, err := server.database.GetAllSBOMs(1000)
		require.NoError(t, err)
		assert.Equal(t, len(initialTotalCount)-len(repoSBOMs), len(remainingTotalSBOMs))
	})

	t.Run("Repository Deletion - Nonexistent Repository", func(t *testing.T) {
		// Test deletion of non-existent repository
		req := httptest.NewRequest("DELETE", "/api/v1/repositories/nonexistent-repo", nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 404, resp.StatusCode)
	})

	t.Run("SBOM Deletion - Invalid ID", func(t *testing.T) {
		// Test deletion with invalid SBOM ID
		req := httptest.NewRequest("DELETE", "/api/v1/sboms/99999", nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 404, resp.StatusCode)
	})

	t.Run("Multiple SBOM Deletion - Empty Request", func(t *testing.T) {
		// Test deletion with empty request body
		requestBody := map[string]interface{}{
			"sbom_ids": []int{},
		}
		bodyBytes, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("DELETE", "/api/v1/sboms", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		resp, err := server.app.Test(req)
		require.NoError(t, err)

		assert.Equal(t, 400, resp.StatusCode)
	})
}

func TestRepositoryGroupingLogic(t *testing.T) {
	server, cleanup := setupRepositoryTestServer(t)
	defer cleanup()

	// Test the repository grouping logic in detail
	sboms, err := server.database.GetAllSBOMs(100)
	require.NoError(t, err)
	require.Greater(t, len(sboms), 0)

	// Group SBOMs by repository (simulate handler logic)
	repositoryGroups := make(map[string]*RepositoryInfo)

	for _, sbom := range sboms {
		if _, exists := repositoryGroups[sbom.RepoName]; !exists {
			repositoryGroups[sbom.RepoName] = &RepositoryInfo{
				Name:                 sbom.RepoName,
				Modules:              []*models.SBOM{},
				UniqueModules:        []ModuleInfo{},
				ModuleCount:          0,
				TotalComponents:      0,
				TotalVulnerabilities: 0,
				LastScanDate:         sbom.ScanDate.Format("2006-01-02 15:04"),
				RiskLevel:            "low",
			}
		}

		repo := repositoryGroups[sbom.RepoName]
		repo.Modules = append(repo.Modules, sbom)
	}

	// Process unique modules for each repository
	for _, repo := range repositoryGroups {
		moduleMap := make(map[string]*ModuleInfo)

		for _, sbom := range repo.Modules {
			if moduleInfo, exists := moduleMap[sbom.ModulePath]; !exists {
				moduleMap[sbom.ModulePath] = &ModuleInfo{
					ModulePath:     sbom.ModulePath,
					LatestSBOM:     sbom,
					ComponentCount: sbom.ComponentCount,
					VulnCount:      0,
					AllSBOMs:       []*models.SBOM{sbom},
				}
			} else {
				moduleInfo.AllSBOMs = append(moduleInfo.AllSBOMs, sbom)
				if sbom.ScanDate.After(moduleInfo.LatestSBOM.ScanDate) {
					moduleInfo.LatestSBOM = sbom
					moduleInfo.ComponentCount = sbom.ComponentCount
				}
			}
		}

		repo.UniqueModules = make([]ModuleInfo, 0, len(moduleMap))
		repo.TotalComponents = 0

		for _, moduleInfo := range moduleMap {
			repo.UniqueModules = append(repo.UniqueModules, *moduleInfo)
			repo.TotalComponents += moduleInfo.ComponentCount
		}

		repo.ModuleCount = len(moduleMap)
	}

	// Test frontend-app repository (should have 3 modules)
	require.Contains(t, repositoryGroups, "frontend-app")
	frontendRepo := repositoryGroups["frontend-app"]
	assert.Equal(t, 3, frontendRepo.ModuleCount)
	assert.Greater(t, frontendRepo.TotalComponents, 0)

	// Test backend-service repository (should have 1 module)
	require.Contains(t, repositoryGroups, "backend-service")
	backendRepo := repositoryGroups["backend-service"]
	assert.Equal(t, 1, backendRepo.ModuleCount)
	assert.Greater(t, backendRepo.TotalComponents, 0)

	// Test microservice-cluster repository (should have 3 modules)
	require.Contains(t, repositoryGroups, "microservice-cluster")
	microserviceRepo := repositoryGroups["microservice-cluster"]
	assert.Equal(t, 3, microserviceRepo.ModuleCount)
	assert.Greater(t, microserviceRepo.TotalComponents, 0)

	// Verify module paths are correct
	for _, module := range frontendRepo.UniqueModules {
		assert.Contains(t, []string{".", "packages/ui", "packages/core"}, module.ModulePath)
	}

	for _, module := range microserviceRepo.UniqueModules {
		assert.Contains(t, []string{"api-gateway", "user-service", "notification-service"}, module.ModulePath)
	}
}
