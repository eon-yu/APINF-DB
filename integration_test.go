package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"oss-compliance-scanner/web"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// APIIntegrationTestSuite contains all API integration tests
type APIIntegrationTestSuite struct {
	suite.Suite
	server   *web.DashboardServer
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
	server := web.NewDashboardServer(database, "0") // Use port 0 for random available port

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
func (suite *APIIntegrationTestSuite) makeAPIRequest(method, endpoint string, body interface{}) (*http.Response, []byte) {
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

	var health map[string]interface{}
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

	var stats map[string]interface{}
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

	var components []map[string]interface{}
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
	var licensesResp interface{}
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
		err := database.CreateSBOM(sbom)
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
		assert.Len(t, licensePolicies, 1)

		vulnPolicies, err := database.GetActiveVulnerabilityPolicies()
		require.NoError(t, err)
		assert.Len(t, vulnPolicies, 1)

		// Test policy deletion
		err = database.DeleteLicensePolicy(licensePolicy.ID)
		require.NoError(t, err)

		remainingPolicies, err := database.GetActiveLicensePolicies()
		require.NoError(t, err)
		assert.Empty(t, remainingPolicies)
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
