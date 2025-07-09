package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oss-compliance-scanner/config"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"oss-compliance-scanner/scanner"
	"oss-compliance-scanner/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// APIIntegrationTestSuite contains all API integration tests
type APIIntegrationTestSuite struct {
	suite.Suite
	server   *web.AppServer
	database *db.Database
	baseURL  string
	cleanup  func()
}

// SetupSuite runs once before all tests in the suite
func (suite *APIIntegrationTestSuite) SetupSuite() {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "api_integration_test_*")
	require.NoError(suite.T(), err)

	// Create test database
	dbPath := filepath.Join(tempDir, "integration_test.db")
	database, err := db.NewDatabase("sqlite3", dbPath)
	require.NoError(suite.T(), err)

	// Create templates directory structure for web server
	templatesDir := filepath.Join(tempDir, "web", "templates", "layouts")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(suite.T(), err)

	// Create minimal template files
	mainTemplate := `<!DOCTYPE html><html><head><title>{{.Title}}</title></head><body>{{embed}}</body></html>`
	err = os.WriteFile(filepath.Join(templatesDir, "main.html"), []byte(mainTemplate), 0644)
	require.NoError(suite.T(), err)

	pagesDir := filepath.Join(tempDir, "web", "templates", "pages")
	err = os.MkdirAll(pagesDir, 0755)
	require.NoError(suite.T(), err)

	pageTemplate := `<h1>{{.Title}}</h1><div>{{.}}</div>`
	pages := []string{"dashboard.html", "sboms.html", "vulnerabilities.html", "policies.html", "violations.html", "reports.html", "admin.html", "sbom_detail.html"}
	for _, page := range pages {
		err = os.WriteFile(filepath.Join(pagesDir, page), []byte(pageTemplate), 0644)
		require.NoError(suite.T(), err)
	}

	// Change working directory for template loading
	originalWD, _ := os.Getwd()
	os.Chdir(tempDir)

	// Create web server
	server := web.NewServer(database, "0") // Use port 0 for random available port

	suite.server = server
	suite.database = database
	suite.baseURL = "http://localhost"

	suite.cleanup = func() {
		server.Stop()
		database.Close()
		os.Chdir(originalWD)
		os.RemoveAll(tempDir)
	}
}

// TearDownSuite runs once after all tests in the suite
func (suite *APIIntegrationTestSuite) TearDownSuite() {
	if suite.cleanup != nil {
		suite.cleanup()
	}
}

// SetupTest runs before each individual test
func (suite *APIIntegrationTestSuite) SetupTest() {
	// Clear all tables before each test
	suite.database.Exec("DELETE FROM vulnerabilities")
	suite.database.Exec("DELETE FROM components")
	suite.database.Exec("DELETE FROM sboms")
	suite.database.Exec("DELETE FROM license_policies")
	suite.database.Exec("DELETE FROM vulnerability_policies")
	suite.database.Exec("DELETE FROM scan_results")
}

// Component represents a component structure for test data
type Component struct {
	Name     string
	Version  string
	Language string
	License  string
	Vulns    []Vulnerability
}

// Vulnerability represents a vulnerability structure for test data
type Vulnerability struct {
	VulnID   string
	Severity string
	CVSS     float64
}

// Repository represents a repository structure for test data
type Repository struct {
	Name       string
	ModulePath string
	Components []Component
}

// createTestData creates comprehensive test data for integration testing
func (suite *APIIntegrationTestSuite) createTestData() {
	// Create multiple repositories with different scenarios
	repos := []Repository{
		{
			Name:       "frontend-app",
			ModulePath: "apps/frontend",
			Components: []Component{
				{
					Name:     "react",
					Version:  "18.2.0",
					Language: "javascript",
					License:  "MIT",
					Vulns: []Vulnerability{
						{"CVE-2023-1001", "Medium", 5.3},
					},
				},
				{
					Name:     "lodash",
					Version:  "4.17.20",
					Language: "javascript",
					License:  "MIT",
					Vulns: []Vulnerability{
						{"CVE-2023-1002", "High", 8.1},
						{"CVE-2023-1003", "Critical", 9.8},
					},
				},
			},
		},
		{
			Name:       "backend-api",
			ModulePath: "apps/backend",
			Components: []Component{
				{
					Name:     "express",
					Version:  "4.18.0",
					Language: "javascript",
					License:  "MIT",
					Vulns:    []Vulnerability{},
				},
				{
					Name:     "mysql2",
					Version:  "2.3.0",
					Language: "javascript",
					License:  "MIT",
					Vulns: []Vulnerability{
						{"CVE-2023-1004", "Low", 3.1},
					},
				},
			},
		},
		{
			Name:       "go-service",
			ModulePath: "services/auth",
			Components: []Component{
				{
					Name:     "github.com/gin-gonic/gin",
					Version:  "1.9.1",
					Language: "go",
					License:  "MIT",
					Vulns:    []Vulnerability{},
				},
				{
					Name:     "github.com/gorilla/websocket",
					Version:  "1.5.0",
					Language: "go",
					License:  "BSD-2-Clause",
					Vulns: []Vulnerability{
						{"CVE-2023-1005", "High", 7.5},
					},
				},
			},
		},
	}

	// Create SBOMs and related data
	for _, repo := range repos {
		// Create SBOM
		sbom := &models.SBOM{
			RepoName:       repo.Name,
			ModulePath:     repo.ModulePath,
			ScanDate:       time.Now().Add(-time.Duration(len(repos)) * time.Hour),
			SyftVersion:    "0.82.0",
			RawSBOM:        fmt.Sprintf(`{"repo": "%s", "components": %d}`, repo.Name, len(repo.Components)),
			ComponentCount: len(repo.Components),
		}
		err := suite.database.CreateSBOM(sbom)
		require.NoError(suite.T(), err)

		// Create components
		for _, comp := range repo.Components {
			component := &models.Component{
				SBOMID:   sbom.ID,
				Name:     comp.Name,
				Version:  comp.Version,
				Type:     "library",
				Language: comp.Language,
				PURL:     fmt.Sprintf("pkg:%s/%s@%s", comp.Language, comp.Name, comp.Version),
				Licenses: []string{comp.License},
			}
			err = suite.database.CreateComponent(component)
			require.NoError(suite.T(), err)

			// Create vulnerabilities
			for _, vuln := range comp.Vulns {
				vulnerability := &models.Vulnerability{
					ComponentID: component.ID,
					VulnID:      vuln.VulnID,
					Severity:    vuln.Severity,
					CVSS3Score:  vuln.CVSS,
					Description: fmt.Sprintf("Test vulnerability %s in %s", vuln.VulnID, comp.Name),
					Fixes:       []models.VulnerabilityFix{{Version: "next-version", State: "fixed"}},
				}
				err = suite.database.CreateVulnerability(vulnerability)
				require.NoError(suite.T(), err)
			}
		}

		// Create scan result
		criticalCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0
		totalVulns := 0

		for _, comp := range repo.Components {
			for _, vuln := range comp.Vulns {
				totalVulns++
				switch vuln.Severity {
				case "Critical":
					criticalCount++
				case "High":
					highCount++
				case "Medium":
					mediumCount++
				case "Low":
					lowCount++
				}
			}
		}

		overallRisk := models.RiskLevelLow
		if criticalCount > 0 {
			overallRisk = models.RiskLevelCritical
		} else if highCount > 0 {
			overallRisk = models.RiskLevelHigh
		} else if mediumCount > 0 {
			overallRisk = models.RiskLevelMedium
		}

		scanResult := &models.ScanResult{
			SBOMID:               sbom.ID,
			RepoName:             repo.Name,
			ModulePath:           repo.ModulePath,
			ScanStartTime:        time.Now().Add(-time.Minute),
			ScanEndTime:          time.Now(),
			Status:               models.ScanStatusCompleted,
			TotalComponents:      len(repo.Components),
			VulnerabilitiesFound: totalVulns,
			LicenseViolations:    0,
			CriticalVulns:        criticalCount,
			HighVulns:            highCount,
			MediumVulns:          mediumCount,
			LowVulns:             lowCount,
			OverallRisk:          overallRisk,
		}
		err = suite.database.CreateScanResult(scanResult)
		require.NoError(suite.T(), err)
	}

	// Create policies with unique names to avoid conflicts
	timestamp := time.Now().UnixNano()
	licensePolicies := []*models.LicensePolicy{
		{
			LicenseName: fmt.Sprintf("GPL-3.0-%d", timestamp),
			Action:      models.PolicyActionBlock,
			Reason:      "Copyleft license not allowed",
			IsActive:    true,
		},
		{
			LicenseName: fmt.Sprintf("AGPL-3.0-%d", timestamp),
			Action:      models.PolicyActionBlock,
			Reason:      "Strong copyleft license",
			IsActive:    true,
		},
		{
			LicenseName: fmt.Sprintf("MIT-%d", timestamp),
			Action:      models.PolicyActionAllow,
			Reason:      "Permissive license",
			IsActive:    true,
		},
	}

	for _, policy := range licensePolicies {
		err := suite.database.CreateLicensePolicy(policy)
		require.NoError(suite.T(), err)
	}

	vulnPolicies := []*models.VulnerabilityPolicy{
		{
			MinSeverityLevel: "Critical",
			Action:           models.PolicyActionFail,
			IsActive:         true,
		},
		{
			MinSeverityLevel: "High",
			Action:           models.PolicyActionWarn,
			IsActive:         true,
		},
	}

	for _, policy := range vulnPolicies {
		err := suite.database.CreateVulnerabilityPolicy(policy)
		require.NoError(suite.T(), err)
	}
}

// makeAPIRequest makes an HTTP request to the API and returns the response
func (suite *APIIntegrationTestSuite) makeAPIRequest(method, endpoint string, body any) (*http.Response, []byte) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		require.NoError(suite.T(), err)
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequest(method, suite.baseURL+endpoint, reqBody)
	require.NoError(suite.T(), err)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Use the test client from fiber
	resp, err := suite.server.Test(req)
	require.NoError(suite.T(), err)

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(suite.T(), err)

	return resp, respBody
}

// Test health check endpoints
func (suite *APIIntegrationTestSuite) TestHealthCheckEndpoints() {
	// Test main health endpoint
	resp, body := suite.makeAPIRequest("GET", "/api/v1/health", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var health map[string]any
	err := json.Unmarshal(body, &health)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "ok", health["status"])

	// Test database health
	resp, body = suite.makeAPIRequest("GET", "/api/v1/health/db", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	err = json.Unmarshal(body, &health)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "ok", health["status"])
}

// Test statistics endpoint
func (suite *APIIntegrationTestSuite) TestStatsEndpoint() {
	suite.createTestData()

	resp, body := suite.makeAPIRequest("GET", "/api/v1/stats", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var stats map[string]any
	err := json.Unmarshal(body, &stats)
	require.NoError(suite.T(), err)

	// Verify expected statistics
	assert.Equal(suite.T(), float64(3), stats["total_sboms"])
	assert.Greater(suite.T(), stats["total_components"], float64(0))
	assert.Greater(suite.T(), stats["total_vulnerabilities"], float64(0))
	// Check for actual fields returned by the API
	assert.Contains(suite.T(), stats, "critical_vulns")
	assert.Contains(suite.T(), stats, "high_vulns")
	assert.Contains(suite.T(), stats, "medium_vulns")
	assert.Contains(suite.T(), stats, "low_vulns")
}

// Test SBOM-related endpoints
func (suite *APIIntegrationTestSuite) TestSBOMEndpoints() {
	suite.createTestData()

	// Test getting all SBOMs
	resp, body := suite.makeAPIRequest("GET", "/api/v1/sboms", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var sboms []*models.SBOM
	err := json.Unmarshal(body, &sboms)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), sboms, 3)

	// Test getting specific SBOM
	sbomID := sboms[0].ID
	resp, body = suite.makeAPIRequest("GET", fmt.Sprintf("/api/v1/sboms/%d", sbomID), nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var sbom models.SBOM
	err = json.Unmarshal(body, &sbom)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), sbomID, sbom.ID)

	// Test getting SBOM components
	resp, body = suite.makeAPIRequest("GET", fmt.Sprintf("/api/v1/sboms/%d/components", sbomID), nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var components []map[string]any
	err = json.Unmarshal(body, &components)
	require.NoError(suite.T(), err)
	assert.Greater(suite.T(), len(components), 0)
	assert.Contains(suite.T(), components[0], "name")
	assert.Contains(suite.T(), components[0], "vulnerability_count")

	// Test getting SBOM vulnerabilities
	resp, body = suite.makeAPIRequest("GET", fmt.Sprintf("/api/v1/sboms/%d/vulnerabilities", sbomID), nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var vulnerabilities []*models.Vulnerability
	err = json.Unmarshal(body, &vulnerabilities)
	require.NoError(suite.T(), err)

	// Test getting SBOM licenses
	resp, body = suite.makeAPIRequest("GET", fmt.Sprintf("/api/v1/sboms/%d/licenses", sbomID), nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// The response could be an object with licenses field or an array
	var licensesResp any
	err = json.Unmarshal(body, &licensesResp)
	require.NoError(suite.T(), err)
	assert.NotNil(suite.T(), licensesResp)
}

// Test vulnerability endpoints
func (suite *APIIntegrationTestSuite) TestVulnerabilityEndpoints() {
	suite.createTestData()

	// Test getting all vulnerabilities
	resp, body := suite.makeAPIRequest("GET", "/api/v1/vulnerabilities", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var vulnerabilities []*models.Vulnerability
	err := json.Unmarshal(body, &vulnerabilities)
	require.NoError(suite.T(), err)
	assert.Greater(suite.T(), len(vulnerabilities), 0)

	// Verify vulnerability data
	found := false
	for _, vuln := range vulnerabilities {
		if vuln.VulnID == "CVE-2023-1002" {
			found = true
			assert.Equal(suite.T(), "High", vuln.Severity)
			assert.Equal(suite.T(), 8.1, vuln.CVSS3Score)
			break
		}
	}
	assert.True(suite.T(), found, "Should find the expected vulnerability")
}

// Test policy management endpoints
func (suite *APIIntegrationTestSuite) TestPolicyManagementEndpoints() {
	suite.createTestData()

	// Test getting license policies
	resp, body := suite.makeAPIRequest("GET", "/api/v1/policies/licenses", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var licensePolicies []*models.LicensePolicy
	err := json.Unmarshal(body, &licensePolicies)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), licensePolicies, 3)

	// Test creating new license policy
	newLicensePolicy := models.LicensePolicy{
		LicenseName: "BSD-3-Clause",
		Action:      models.PolicyActionAllow,
		Reason:      "Permissive license",
		IsActive:    true,
	}

	resp, body = suite.makeAPIRequest("POST", "/api/v1/policies/licenses", newLicensePolicy)
	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)

	var newPolicy models.LicensePolicy
	err = json.Unmarshal(body, &newPolicy)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "BSD-3-Clause", newPolicy.LicenseName)

	// Test getting vulnerability policies
	resp, body = suite.makeAPIRequest("GET", "/api/v1/policies/vulnerabilities", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var vulnPolicies []*models.VulnerabilityPolicy
	err = json.Unmarshal(body, &vulnPolicies)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), vulnPolicies, 2)

	// Test creating new vulnerability policy
	newVulnPolicy := models.VulnerabilityPolicy{
		MinSeverityLevel: "Medium",
		Action:           models.PolicyActionWarn,
		IsActive:         true,
	}

	resp, body = suite.makeAPIRequest("POST", "/api/v1/policies/vulnerabilities", newVulnPolicy)
	assert.Equal(suite.T(), http.StatusCreated, resp.StatusCode)

	// Test deleting license policy
	policyID := licensePolicies[0].ID
	resp, _ = suite.makeAPIRequest("DELETE", fmt.Sprintf("/api/v1/policies/licenses/%d", policyID), nil)
	assert.Equal(suite.T(), http.StatusNoContent, resp.StatusCode)

	// Verify policy was deleted
	resp, body = suite.makeAPIRequest("GET", "/api/v1/policies/licenses", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var remainingPolicies []*models.LicensePolicy
	err = json.Unmarshal(body, &remainingPolicies)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), remainingPolicies, 3) // 2 original + 1 newly created
}

// Test scan results endpoints
func (suite *APIIntegrationTestSuite) TestScanResultsEndpoints() {
	suite.createTestData()

	resp, body := suite.makeAPIRequest("GET", "/api/v1/scan-results", nil)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	var scanResults []*models.ScanResult
	err := json.Unmarshal(body, &scanResults)
	require.NoError(suite.T(), err)
	assert.Len(suite.T(), scanResults, 3)

	// Verify scan result data
	for _, result := range scanResults {
		assert.Equal(suite.T(), models.ScanStatusCompleted, result.Status)
		assert.Greater(suite.T(), result.TotalComponents, 0)
		assert.GreaterOrEqual(suite.T(), result.VulnerabilitiesFound, 0)
	}
}

// Test error handling across endpoints
func (suite *APIIntegrationTestSuite) TestErrorHandling() {
	// Test invalid SBOM ID
	resp, _ := suite.makeAPIRequest("GET", "/api/v1/sboms/invalid", nil)
	assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)

	// Test non-existent SBOM
	resp, _ = suite.makeAPIRequest("GET", "/api/v1/sboms/999999", nil)
	assert.Equal(suite.T(), http.StatusNotFound, resp.StatusCode)

	// Test invalid component ID
	resp, _ = suite.makeAPIRequest("GET", "/api/v1/components/invalid", nil)
	assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)

	// Test invalid policy ID for deletion
	resp, _ = suite.makeAPIRequest("DELETE", "/api/v1/policies/licenses/invalid", nil)
	assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)
}

// TestAPIIntegrationSuite runs the entire test suite
func TestAPIIntegrationSuite(t *testing.T) {
	suite.Run(t, new(APIIntegrationTestSuite))
}

// End-to-end integration test for complete workflows
func TestEndToEndWorkflows(t *testing.T) {
	// Test complete SBOM workflow
	t.Run("Complete SBOM Workflow", func(t *testing.T) {
		// Create temporary directory
		tempDir, err := os.MkdirTemp("", "e2e_sbom_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// Create test database
		dbPath := filepath.Join(tempDir, "e2e_sbom_test.db")
		database, err := db.NewDatabase("sqlite3", dbPath)
		require.NoError(t, err)
		defer database.Close()

		// Create SBOM
		sbom := &models.SBOM{
			RepoName:       "e2e-test-repo",
			ModulePath:     ".",
			ScanDate:       time.Now(),
			SyftVersion:    "0.82.0",
			RawSBOM:        `{"test": "e2e data"}`,
			ComponentCount: 1,
		}
		err = database.CreateSBOM(sbom)
		require.NoError(t, err)
		assert.Greater(t, sbom.ID, 0)

		// Add component
		component := &models.Component{
			SBOMID:   sbom.ID,
			Name:     "e2e-component",
			Version:  "1.0.0",
			Type:     "library",
			Language: "javascript",
			Licenses: []string{"MIT"},
		}
		err = database.CreateComponent(component)
		require.NoError(t, err)

		// Add vulnerability
		vulnerability := &models.Vulnerability{
			ComponentID: component.ID,
			VulnID:      "CVE-2023-E2E",
			Severity:    "High",
			CVSS3Score:  7.8,
			Description: "End-to-end test vulnerability",
		}
		err = database.CreateVulnerability(vulnerability)
		require.NoError(t, err)

		// Verify data integrity
		retrievedSBOM, err := database.GetSBOM(sbom.ID)
		require.NoError(t, err)
		assert.Equal(t, sbom.RepoName, retrievedSBOM.RepoName)

		components, err := database.GetComponentsBySBOM(sbom.ID)
		require.NoError(t, err)
		assert.Len(t, components, 1)

		vulnerabilities, err := database.GetVulnerabilitiesByComponent(component.ID)
		require.NoError(t, err)
		assert.Len(t, vulnerabilities, 1)
		assert.Equal(t, "CVE-2023-E2E", vulnerabilities[0].VulnID)
	})

	// Test policy workflow
	t.Run("Complete Policy Workflow", func(t *testing.T) {
		// Create temporary directory
		tempDir, err := os.MkdirTemp("", "e2e_policy_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// Create test database
		dbPath := filepath.Join(tempDir, "e2e_policy_test.db")
		database, err := db.NewDatabase("sqlite3", dbPath)
		require.NoError(t, err)
		defer database.Close()

		// Run migrations to ensure tables exist
		err = database.RunMigrations()
		require.NoError(t, err)

		// Create license policy
		timestamp := time.Now().UnixNano()
		licensePolicy := &models.LicensePolicy{
			LicenseName: fmt.Sprintf("GPL-2.0-%d", timestamp),
			Action:      models.PolicyActionBlock,
			Reason:      "Copyleft license",
			IsActive:    true,
		}
		err = database.CreateLicensePolicy(licensePolicy)
		require.NoError(t, err)

		// Create vulnerability policy
		vulnPolicy := &models.VulnerabilityPolicy{
			MinSeverityLevel: "Critical",
			Action:           models.PolicyActionFail,
			IsActive:         true,
		}
		err = database.CreateVulnerabilityPolicy(vulnPolicy)
		require.NoError(t, err)

		// Verify policies can be retrieved
		licensePolicies, err := database.GetActiveLicensePolicies()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(licensePolicies), 1) // Should have at least our created policy + default policies

		vulnPolicies, err := database.GetActiveVulnerabilityPolicies()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(vulnPolicies), 1) // Should have at least our created policy + default policies

		// Verify our specific policy exists
		var foundLicensePolicy bool
		for _, policy := range licensePolicies {
			if policy.LicenseName == licensePolicy.LicenseName {
				foundLicensePolicy = true
				break
			}
		}
		assert.True(t, foundLicensePolicy, "Should find the created license policy")

		// Test policy deletion
		err = database.DeleteLicensePolicy(licensePolicy.ID)
		require.NoError(t, err)

		remainingPolicies, err := database.GetActiveLicensePolicies()
		require.NoError(t, err)

		// Verify our specific policy was deleted (but default policies remain)
		var foundAfterDeletion bool
		for _, policy := range remainingPolicies {
			if policy.LicenseName == licensePolicy.LicenseName {
				foundAfterDeletion = true
				break
			}
		}
		assert.False(t, foundAfterDeletion, "Our specific policy should be deleted")
		assert.GreaterOrEqual(t, len(remainingPolicies), 11) // Default policies should remain
	})

	// Test scan result workflow
	t.Run("Complete Scan Result Workflow", func(t *testing.T) {
		// Create temporary directory
		tempDir, err := os.MkdirTemp("", "e2e_scan_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// Create test database
		dbPath := filepath.Join(tempDir, "e2e_scan_test.db")
		database, err := db.NewDatabase("sqlite3", dbPath)
		require.NoError(t, err)
		defer database.Close()

		// Run migrations to ensure tables exist
		err = database.RunMigrations()
		require.NoError(t, err)

		// Create SBOM for scan result
		sbom := &models.SBOM{
			RepoName:       "scan-test-repo",
			ModulePath:     ".",
			ScanDate:       time.Now(),
			SyftVersion:    "0.82.0",
			RawSBOM:        `{"scan": "test"}`,
			ComponentCount: 2,
		}
		err = database.CreateSBOM(sbom)
		require.NoError(t, err)

		// Create scan result
		scanResult := &models.ScanResult{
			SBOMID:               sbom.ID,
			RepoName:             "scan-test-repo",
			ModulePath:           ".",
			ScanStartTime:        time.Now().Add(-5 * time.Minute),
			ScanEndTime:          time.Now(),
			Status:               models.ScanStatusCompleted,
			TotalComponents:      2,
			VulnerabilitiesFound: 3,
			LicenseViolations:    1,
			CriticalVulns:        1,
			HighVulns:            1,
			MediumVulns:          1,
			LowVulns:             0,
			OverallRisk:          models.RiskLevelCritical,
		}
		err = database.CreateScanResult(scanResult)
		require.NoError(t, err)

		// Verify scan result
		scanResults, err := database.GetLatestScanResults(10)
		require.NoError(t, err)
		assert.Greater(t, len(scanResults), 0)

		found := false
		for _, result := range scanResults {
			if result.SBOMID == sbom.ID {
				found = true
				assert.Equal(t, models.ScanStatusCompleted, result.Status)
				assert.Equal(t, models.RiskLevelCritical, result.OverallRisk)
				assert.Equal(t, 3, result.VulnerabilitiesFound)
				break
			}
		}
		assert.True(t, found, "Should find the created scan result")
	})
}

func TestCppProjectScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test C++ project scanning with Conan package manager
	testDir := "test-projects/cpp-app"

	// Convert to absolute path
	absTestDir, err := filepath.Abs(testDir)
	require.NoError(t, err)

	// Verify test project exists
	if _, err := os.Stat(absTestDir); os.IsNotExist(err) {
		t.Skipf("Test project %s does not exist", absTestDir)
	}

	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "cpp_integration_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize components
	cfg, err := config.LoadConfig("")
	require.NoError(t, err)

	// Create test database
	dbPath := filepath.Join(tempDir, "cpp_test.db")
	database, err := db.NewDatabase("sqlite3", dbPath)
	require.NoError(t, err)
	defer database.Close()

	// Run migrations using the database's migration system
	err = database.RunMigrations()
	require.NoError(t, err)

	syftScanner := scanner.NewSyftScanner(
		cfg.Scanner.SyftPath,
		cfg.Scanner.TempDir,
		cfg.Scanner.CacheDir,
		cfg.Scanner.TimeoutSeconds,
	)

	grypeScanner := scanner.NewGrypeScanner(
		cfg.Scanner.GrypePath,
		cfg.Scanner.TempDir,
		cfg.Scanner.CacheDir,
		cfg.Scanner.TimeoutSeconds,
	)

	ctx := context.Background()

	// Test SBOM generation for C++ project
	t.Run("GeneratesSBOMForCppProject", func(t *testing.T) {
		sbom, err := syftScanner.GenerateSBOM(ctx, absTestDir, nil)
		require.NoError(t, err)
		assert.NotNil(t, sbom)
		assert.Contains(t, sbom.RepoName, "Dependency Bot") // Actual repo name from git
		assert.Equal(t, "test-projects/cpp-app", sbom.ModulePath)
		assert.NotEmpty(t, sbom.RawSBOM)

		// Parse components from SBOM
		components, err := syftScanner.ParseSBOMToComponents(sbom)
		require.NoError(t, err)
		assert.NotEmpty(t, components)

		// Verify C++ components are detected
		expectedComponents := map[string]bool{
			"boost":         false,
			"openssl":       false,
			"libcurl":       false,
			"zlib":          false,
			"nlohmann_json": false,
			"spdlog":        false,
			"fmt":           false,
			"gtest":         false,
		}

		for _, comp := range components {
			if _, exists := expectedComponents[comp.Name]; exists {
				expectedComponents[comp.Name] = true
				assert.Equal(t, "conan", comp.Type, "Expected component type to be 'conan' for %s", comp.Name)
				assert.Equal(t, "c++", comp.Language, "Expected language to be 'c++' for %s", comp.Name)
				assert.NotEmpty(t, comp.Version, "Expected version to be set for %s", comp.Name)
				assert.NotEmpty(t, comp.PURL, "Expected PURL to be set for %s", comp.Name)
			}
		}

		// Verify all expected components were found
		for name, found := range expectedComponents {
			assert.True(t, found, "Expected to find C++ component: %s", name)
		}

		t.Logf("Found %d C++ components", len(components))
	})

	// Test vulnerability scanning for C++ project
	t.Run("ScansVulnerabilitiesForCppProject", func(t *testing.T) {
		vulns, err := grypeScanner.ScanDirectory(ctx, absTestDir, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, vulns, "Expected to find vulnerabilities in C++ project")

		// Check for known vulnerable components
		hasOpenSSLVuln := false
		hasZlibVuln := false
		hasCurlVuln := false

		for _, vuln := range vulns {
			if strings.Contains(strings.ToLower(vuln.VulnID), "openssl") ||
				strings.Contains(strings.ToLower(vuln.Description), "openssl") {
				hasOpenSSLVuln = true
			}
			if strings.Contains(strings.ToLower(vuln.VulnID), "zlib") ||
				strings.Contains(strings.ToLower(vuln.Description), "zlib") {
				hasZlibVuln = true
			}
			if strings.Contains(strings.ToLower(vuln.VulnID), "curl") ||
				strings.Contains(strings.ToLower(vuln.Description), "curl") {
				hasCurlVuln = true
			}

			// Verify vulnerability structure
			assert.NotEmpty(t, vuln.VulnID, "Vulnerability ID should not be empty")
			assert.NotEmpty(t, vuln.Severity, "Severity should not be empty")
			assert.NotZero(t, vuln.CVSS3Score, "CVSS3 score should be set")
		}

		t.Logf("Found %d vulnerabilities", len(vulns))
		t.Logf("OpenSSL vulnerabilities found: %v", hasOpenSSLVuln)
		t.Logf("Zlib vulnerabilities found: %v", hasZlibVuln)
		t.Logf("Curl vulnerabilities found: %v", hasCurlVuln)

		// We expect to find vulnerabilities in these commonly vulnerable libraries
		assert.True(t, hasOpenSSLVuln || hasZlibVuln, "Expected to find vulnerabilities in OpenSSL or zlib")
	})

	// Test end-to-end C++ project scanning
	t.Run("EndToEndCppProjectScan", func(t *testing.T) {
		// Generate SBOM
		sbom, err := syftScanner.GenerateSBOM(ctx, absTestDir, nil)
		require.NoError(t, err)

		// Save SBOM to database
		err = database.CreateSBOM(sbom)
		require.NoError(t, err)
		assert.NotZero(t, sbom.ID)

		// Parse and save components
		components, err := syftScanner.ParseSBOMToComponents(sbom)
		require.NoError(t, err)

		for _, comp := range components {
			err = database.CreateComponent(comp)
			require.NoError(t, err)
			assert.NotZero(t, comp.ID)
		}

		// Scan vulnerabilities
		vulns, err := grypeScanner.ScanDirectory(ctx, absTestDir, nil)
		require.NoError(t, err)

		// Save vulnerabilities (simplified - link to first component)
		if len(components) > 0 && len(vulns) > 0 {
			for i, vuln := range vulns {
				if i >= 5 { // Limit to first 5 vulnerabilities for test
					break
				}
				vuln.ComponentID = components[0].ID
				err = database.CreateVulnerability(vuln)
				require.NoError(t, err)
				assert.NotZero(t, vuln.ID)
			}
		}

		// Verify data in database
		savedSBOMs, err := database.GetAllSBOMs(10)
		require.NoError(t, err)

		found := false
		for _, savedSBOM := range savedSBOMs {
			if strings.Contains(savedSBOM.RepoName, "Dependency Bot") && savedSBOM.ModulePath == "test-projects/cpp-app" {
				found = true
				assert.Equal(t, "test-projects/cpp-app", savedSBOM.ModulePath)
				assert.NotZero(t, savedSBOM.ComponentCount)
				break
			}
		}
		assert.True(t, found, "C++ project SBOM should be saved in database")

		t.Logf("Successfully completed end-to-end C++ project scan")
	})
}

func TestCLanguageVsCppDistinction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test C vs C++ language distinction
	cTestDir := "test-projects/c-app"
	cppTestDir := "test-projects/cpp-app"

	// Convert to absolute paths
	absCTestDir, err := filepath.Abs(cTestDir)
	require.NoError(t, err)
	absCppTestDir, err := filepath.Abs(cppTestDir)
	require.NoError(t, err)

	// Verify test projects exist
	if _, err := os.Stat(absCTestDir); os.IsNotExist(err) {
		t.Skipf("C test project %s does not exist", absCTestDir)
	}
	if _, err := os.Stat(absCppTestDir); os.IsNotExist(err) {
		t.Skipf("C++ test project %s does not exist", absCppTestDir)
	}

	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "c_vs_cpp_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize components
	cfg, err := config.LoadConfig("")
	require.NoError(t, err)

	// Create test database
	dbPath := filepath.Join(tempDir, "c_vs_cpp_test.db")
	database, err := db.NewDatabase("sqlite3", dbPath)
	require.NoError(t, err)
	defer database.Close()

	err = database.RunMigrations()
	require.NoError(t, err)

	syftScanner := scanner.NewSyftScanner(
		cfg.Scanner.SyftPath,
		cfg.Scanner.TempDir,
		cfg.Scanner.CacheDir,
		cfg.Scanner.TimeoutSeconds,
	)

	ctx := context.Background()

	// Test C language detection
	t.Run("DetectsCLanguage", func(t *testing.T) {
		// Test language detection function directly
		lang := scanner.DetectLanguageFromDirectory(absCTestDir)
		assert.Equal(t, "c", lang, "Should detect C language in c-app project")

		// Test ecosystem determination
		ecosystem := scanner.DetermineEcosystemFromBuildFiles(absCTestDir)
		assert.Equal(t, "make-c", ecosystem, "Should detect make-c ecosystem for C project")
	})

	// Test C++ language detection
	t.Run("DetectsCppLanguage", func(t *testing.T) {
		// Test language detection function directly
		lang := scanner.DetectLanguageFromDirectory(absCppTestDir)
		assert.Equal(t, "cpp", lang, "Should detect C++ language in cpp-app project")

		// Test ecosystem determination for C++ package managers
		ecosystem := scanner.DetermineEcosystemFromBuildFiles(absCppTestDir)
		assert.True(t, ecosystem == "conan" || ecosystem == "cmake-cpp" || ecosystem == "vcpkg",
			"Should detect conan, cmake-cpp, or vcpkg ecosystem for C++ project, got: %s", ecosystem)
	})

	// Test file extension distinction
	t.Run("DistinguishesFileExtensions", func(t *testing.T) {
		// Verify C project has .c files
		found_c_files := false
		err := filepath.Walk(absCTestDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.HasSuffix(path, ".c") {
				found_c_files = true
			}
			// Should not have C++ extensions
			assert.False(t, strings.HasSuffix(path, ".cpp"), "C project should not have .cpp files")
			assert.False(t, strings.HasSuffix(path, ".hpp"), "C project should not have .hpp files")
			return nil
		})
		require.NoError(t, err)
		assert.True(t, found_c_files, "C project should have .c files")

		// Verify C++ project has .cpp files
		found_cpp_files := false
		err = filepath.Walk(absCppTestDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if strings.HasSuffix(path, ".cpp") {
				found_cpp_files = true
			}
			return nil
		})
		require.NoError(t, err)
		assert.True(t, found_cpp_files, "C++ project should have .cpp files")
	})

	// Test build system distinction
	t.Run("DistinguishesBuildSystems", func(t *testing.T) {
		// C project should have Makefile
		makefilePath := filepath.Join(absCTestDir, "Makefile")
		_, err := os.Stat(makefilePath)
		assert.NoError(t, err, "C project should have Makefile")

		// C++ project should have modern package managers
		conanfilePath := filepath.Join(absCppTestDir, "conanfile.txt")
		cmakefilePath := filepath.Join(absCppTestDir, "CMakeLists.txt")
		vcpkgPath := filepath.Join(absCppTestDir, "vcpkg.json")

		hasConan := false
		hasCMake := false
		hasVcpkg := false

		if _, err := os.Stat(conanfilePath); err == nil {
			hasConan = true
		}
		if _, err := os.Stat(cmakefilePath); err == nil {
			hasCMake = true
		}
		if _, err := os.Stat(vcpkgPath); err == nil {
			hasVcpkg = true
		}

		assert.True(t, hasConan || hasCMake || hasVcpkg,
			"C++ project should have at least one modern package manager file")
	})

	// Test SBOM generation differences (if components are found)
	t.Run("GeneratesDifferentSBOMs", func(t *testing.T) {
		// Generate SBOM for C project
		cSbom, err := syftScanner.GenerateSBOM(ctx, absCTestDir, nil)
		require.NoError(t, err)
		assert.NotNil(t, cSbom)

		// Generate SBOM for C++ project
		cppSbom, err := syftScanner.GenerateSBOM(ctx, absCppTestDir, nil)
		require.NoError(t, err)
		assert.NotNil(t, cppSbom)

		// Parse components
		cComponents, err := syftScanner.ParseSBOMToComponents(cSbom)
		require.NoError(t, err)

		cppComponents, err := syftScanner.ParseSBOMToComponents(cppSbom)
		require.NoError(t, err)

		// C++ project should have more modern dependencies
		assert.Greater(t, len(cppComponents), len(cComponents),
			"C++ project should typically have more packaged dependencies than C project")

		// Check for C++ specific libraries in C++ project
		if len(cppComponents) > 0 {
			foundCppLibraries := false
			for _, comp := range cppComponents {
				if strings.Contains(comp.Name, "boost") ||
					strings.Contains(comp.Name, "nlohmann") ||
					strings.Contains(comp.Name, "spdlog") {
					foundCppLibraries = true
					assert.Equal(t, "c++", comp.Language, "C++ libraries should be marked as c++ language")
					break
				}
			}
			assert.True(t, foundCppLibraries, "C++ project should contain C++ specific libraries")
		}

		t.Logf("C project components: %d", len(cComponents))
		t.Logf("C++ project components: %d", len(cppComponents))
	})
}
