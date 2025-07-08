package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// setupTestServer creates a test server with in-memory database
func setupTestServer(t *testing.T) (*DashboardServer, func()) {
	// Create temporary directory for test database
	tempDir, err := os.MkdirTemp("", "web_test_*")
	require.NoError(t, err)

	dbPath := filepath.Join(tempDir, "test.db")
	database, err := db.NewDatabase("sqlite3", dbPath)
	require.NoError(t, err)

	// Create templates directory
	templatesDir := filepath.Join(tempDir, "web", "templates", "layouts")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)

	// Create a minimal main layout template
	mainTemplate := `<!DOCTYPE html>
<html>
<head><title>{{.Title}}</title></head>
<body>{{embed}}</body>
</html>`
	err = os.WriteFile(filepath.Join(templatesDir, "main.html"), []byte(mainTemplate), 0644)
	require.NoError(t, err)

	// Create page templates
	pagesDir := filepath.Join(tempDir, "web", "templates", "pages")
	err = os.MkdirAll(pagesDir, 0755)
	require.NoError(t, err)

	pageTemplate := `<h1>{{.Title}}</h1><div>{{.}}</div>`
	pages := []string{"dashboard.html", "sboms.html", "vulnerabilities.html", "policies.html", "violations.html", "reports.html", "admin.html", "sbom_detail.html"}
	for _, page := range pages {
		err = os.WriteFile(filepath.Join(pagesDir, page), []byte(pageTemplate), 0644)
		require.NoError(t, err)
	}

	// Change working directory temporarily for template loading
	originalWD, _ := os.Getwd()
	os.Chdir(tempDir)

	server := NewDashboardServer(database, "8080")

	cleanup := func() {
		os.Chdir(originalWD)
		database.Close()
		os.RemoveAll(tempDir)
	}

	return server, cleanup
}

// createTestData creates sample data for testing
func createTestData(t *testing.T, database *db.Database) (int, int) {
	// Create SBOM
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 2,
	}
	err := database.CreateSBOM(sbom)
	require.NoError(t, err)

	// Create components
	component1 := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "test-component-1",
		Version:  "1.0.0",
		Type:     "library",
		Language: "javascript",
		PURL:     "pkg:npm/test-component-1@1.0.0",
		Licenses: []string{"MIT"},
	}
	err = database.CreateComponent(component1)
	require.NoError(t, err)

	component2 := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "vulnerable-component",
		Version:  "2.0.0",
		Type:     "library",
		Language: "javascript",
		PURL:     "pkg:npm/vulnerable-component@2.0.0",
		Licenses: []string{"Apache-2.0"},
	}
	err = database.CreateComponent(component2)
	require.NoError(t, err)

	// Create vulnerability
	vulnerability := &models.Vulnerability{
		ComponentID: component2.ID,
		VulnID:      "CVE-2023-1234",
		Severity:    "High",
		CVSS3Score:  7.5,
		Description: "Test vulnerability",
		Fixes:       []models.VulnerabilityFix{{Version: "2.1.0", State: "fixed"}},
	}
	err = database.CreateVulnerability(vulnerability)
	require.NoError(t, err)

	// Create policies
	licensePolicy := &models.LicensePolicy{
		LicenseName: "GPL-3.0",
		Action:      models.PolicyActionBlock,
		IsActive:    true,
		Reason:      "Copyleft license not allowed",
	}
	err = database.CreateLicensePolicy(licensePolicy)
	require.NoError(t, err)

	vulnPolicy := &models.VulnerabilityPolicy{
		MinSeverityLevel: "High",
		Action:           models.PolicyActionFail,
		IsActive:         true,
	}
	err = database.CreateVulnerabilityPolicy(vulnPolicy)
	require.NoError(t, err)

	// Create scan result
	scanResult := &models.ScanResult{
		SBOMID:               sbom.ID,
		RepoName:             "test-repo",
		ModulePath:           ".",
		ScanStartTime:        time.Now().Add(-time.Minute),
		ScanEndTime:          time.Now(),
		Status:               models.ScanStatusCompleted,
		TotalComponents:      2,
		VulnerabilitiesFound: 1,
		LicenseViolations:    0,
		CriticalVulns:        0,
		HighVulns:            1,
		MediumVulns:          0,
		LowVulns:             0,
		OverallRisk:          models.RiskLevelHigh,
	}
	err = database.CreateScanResult(scanResult)
	require.NoError(t, err)

	return sbom.ID, component2.ID
}

func TestNewDashboardServer(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	assert.NotNil(t, server)
	assert.NotNil(t, server.app)
	assert.NotNil(t, server.database)
	assert.Equal(t, "8080", server.port)
}

func TestHealthCheckEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	assert.Equal(t, "ok", response["status"])
}

func TestStatsEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	sbomID, _ := createTestData(t, server.database)

	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var stats map[string]interface{}
	err = json.Unmarshal(body, &stats)
	require.NoError(t, err)

	assert.Contains(t, stats, "total_sboms")
	assert.Contains(t, stats, "total_vulnerabilities")
	assert.Contains(t, stats, "total_components")

	// Verify the test data is reflected in stats
	assert.Equal(t, float64(1), stats["total_sboms"])
	assert.Equal(t, float64(1), stats["total_vulnerabilities"])

	_ = sbomID // Use sbomID to avoid unused variable warning
}

func TestSBOMsAPIEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	sbomID, _ := createTestData(t, server.database)

	req := httptest.NewRequest("GET", "/api/v1/sboms", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var sboms []*models.SBOM
	err = json.Unmarshal(body, &sboms)
	require.NoError(t, err)

	assert.Len(t, sboms, 1)
	assert.Equal(t, sbomID, sboms[0].ID)
	assert.Equal(t, "test-repo", sboms[0].RepoName)
}

func TestSBOMDetailAPIEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	sbomID, _ := createTestData(t, server.database)

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/sboms/%d", sbomID), nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var sbom models.SBOM
	err = json.Unmarshal(body, &sbom)
	require.NoError(t, err)

	assert.Equal(t, sbomID, sbom.ID)
	assert.Equal(t, "test-repo", sbom.RepoName)
}

func TestSBOMDetailAPIEndpoint_NotFound(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/sboms/999", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestComponentsAPIEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	sbomID, _ := createTestData(t, server.database)

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/sboms/%d/components", sbomID), nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var components []map[string]interface{}
	err = json.Unmarshal(body, &components)
	require.NoError(t, err)

	assert.Len(t, components, 2)
	assert.Contains(t, components[0], "name")
	assert.Contains(t, components[0], "vulnerability_count")
}

func TestVulnerabilitiesAPIEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	sbomID, _ := createTestData(t, server.database)

	// Test SBOM-specific vulnerabilities
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/sboms/%d/vulnerabilities", sbomID), nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var vulnerabilities []*models.Vulnerability
	err = json.Unmarshal(body, &vulnerabilities)
	require.NoError(t, err)

	assert.Len(t, vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-1234", vulnerabilities[0].VulnID)
	assert.Equal(t, "High", vulnerabilities[0].Severity)
}

func TestAllVulnerabilitiesAPIEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	_, _ = createTestData(t, server.database)

	req := httptest.NewRequest("GET", "/api/v1/vulnerabilities", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var vulnerabilities []*models.Vulnerability
	err = json.Unmarshal(body, &vulnerabilities)
	require.NoError(t, err)

	assert.Len(t, vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-1234", vulnerabilities[0].VulnID)
}

func TestLicensePoliciesAPIEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	_, _ = createTestData(t, server.database)

	req := httptest.NewRequest("GET", "/api/v1/policies/licenses", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var policies []*models.LicensePolicy
	err = json.Unmarshal(body, &policies)
	require.NoError(t, err)

	assert.Len(t, policies, 1)
	assert.Equal(t, "GPL-3.0", policies[0].LicenseName)
	assert.Equal(t, models.PolicyActionBlock, policies[0].Action)
}

func TestCreateLicensePolicyAPI(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	newPolicy := models.LicensePolicy{
		LicenseName: "AGPL-3.0",
		Action:      models.PolicyActionBlock,
		Reason:      "Strong copyleft license",
		IsActive:    true,
	}

	jsonData, err := json.Marshal(newPolicy)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/policies/licenses", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	assert.Equal(t, "Policy created successfully", response["message"])
}

func TestCreateVulnerabilityPolicyAPI(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	newPolicy := models.VulnerabilityPolicy{
		MinSeverityLevel: "Medium",
		Action:           models.PolicyActionWarn,
		IsActive:         true,
	}

	jsonData, err := json.Marshal(newPolicy)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/policies/vulnerabilities", bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

func TestDeleteLicensePolicyAPI(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	_, _ = createTestData(t, server.database)

	// First get the policy ID
	policies, err := server.database.GetActiveLicensePolicies()
	require.NoError(t, err)
	require.Len(t, policies, 1)

	policyID := policies[0].ID

	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/policies/licenses/%d", policyID), nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify policy was deleted
	remainingPolicies, err := server.database.GetActiveLicensePolicies()
	require.NoError(t, err)
	assert.Empty(t, remainingPolicies)
}

func TestScanResultsAPIEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	_, _ = createTestData(t, server.database)

	req := httptest.NewRequest("GET", "/api/v1/scan-results", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var scanResults []*models.ScanResult
	err = json.Unmarshal(body, &scanResults)
	require.NoError(t, err)

	assert.Len(t, scanResults, 1)
	assert.Equal(t, "test-repo", scanResults[0].RepoName)
	assert.Equal(t, models.ScanStatusCompleted, scanResults[0].Status)
}

func TestHealthDBEndpoint(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/v1/health/db", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	assert.Equal(t, "ok", response["status"])
	assert.Contains(t, response, "message")
}

func TestInvalidIDHandling(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test invalid SBOM ID
	req := httptest.NewRequest("GET", "/api/v1/sboms/invalid", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Test non-existent SBOM ID
	req = httptest.NewRequest("GET", "/api/v1/sboms/999", nil)
	resp, err = server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestInvalidJSONHandling(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test invalid JSON for creating license policy
	invalidJSON := `{"invalid": json}`

	req := httptest.NewRequest("POST", "/api/v1/policies/licenses", bytes.NewReader([]byte(invalidJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestWebPageHandlers(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	_, _ = createTestData(t, server.database)

	// Test dashboard page
	req := httptest.NewRequest("GET", "/", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test SBOMs page
	req = httptest.NewRequest("GET", "/sboms", nil)
	resp, err = server.app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test vulnerabilities page
	req = httptest.NewRequest("GET", "/vulnerabilities", nil)
	resp, err = server.app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test policies page
	req = httptest.NewRequest("GET", "/policies", nil)
	resp, err = server.app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSBOMDetailWebPage(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	sbomID, _ := createTestData(t, server.database)

	req := httptest.NewRequest("GET", fmt.Sprintf("/sboms/%d", sbomID), nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Test invalid SBOM ID for web page
	req = httptest.NewRequest("GET", "/sboms/invalid", nil)
	resp, err = server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestComponentDetailAPI(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	_, componentID := createTestData(t, server.database)

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/components/%d", componentID), nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	require.NoError(t, err)

	assert.Contains(t, response, "component")
	assert.Contains(t, response, "vulnerabilities")

	component := response["component"].(map[string]interface{})
	assert.Equal(t, "vulnerable-component", component["name"])
}

func TestLicensesBySBOMAPI(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	sbomID, _ := createTestData(t, server.database)

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/sboms/%d/licenses", sbomID), nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var licenses []map[string]interface{}
	err = json.Unmarshal(body, &licenses)
	require.NoError(t, err)

	assert.Len(t, licenses, 2) // MIT and Apache-2.0

	// Check that licenses are grouped correctly
	foundMIT := false
	foundApache := false
	for _, license := range licenses {
		if license["license"] == "MIT" {
			foundMIT = true
			assert.Equal(t, float64(1), license["count"])
		}
		if license["license"] == "Apache-2.0" {
			foundApache = true
			assert.Equal(t, float64(1), license["count"])
		}
	}
	assert.True(t, foundMIT, "Should find MIT license")
	assert.True(t, foundApache, "Should find Apache-2.0 license")
}

func TestCORSAndMiddleware(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Origin"), "*")
}

func TestServerStartStop(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test that Start and Stop don't panic
	assert.NotPanics(t, func() {
		// We can't actually start the server in tests, but we can ensure the method exists
		assert.NotNil(t, server.Start)
		assert.NotNil(t, server.Stop)
	})
}

func TestAPIRoutes(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test that all expected API routes exist by checking they don't return 404
	apiRoutes := []string{
		"/api/v1/health",
		"/api/v1/stats",
		"/api/v1/sboms",
		"/api/v1/vulnerabilities",
		"/api/v1/scan-results",
		"/api/v1/policies/licenses",
		"/api/v1/policies/vulnerabilities",
		"/api/v1/health/db",
	}

	for _, route := range apiRoutes {
		req := httptest.NewRequest("GET", route, nil)
		resp, err := server.app.Test(req)
		require.NoError(t, err)
		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode, "Route %s should not return 404", route)
	}
}

func TestErrorHandling(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test error handling when database operations fail
	// This is difficult to test without mocking, but we can test invalid parameters

	// Invalid policy ID for deletion
	req := httptest.NewRequest("DELETE", "/api/v1/policies/licenses/invalid", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Invalid vulnerability policy ID for deletion
	req = httptest.NewRequest("DELETE", "/api/v1/policies/vulnerabilities/invalid", nil)
	resp, err = server.app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestPaginationLimits(t *testing.T) {
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Create multiple SBOMs to test pagination
	for i := 0; i < 10; i++ {
		sbom := &models.SBOM{
			RepoName:       fmt.Sprintf("test-repo-%d", i),
			ModulePath:     ".",
			ScanDate:       time.Now(),
			SyftVersion:    "0.82.0",
			RawSBOM:        `{"test": "data"}`,
			ComponentCount: 1,
		}
		err := server.database.CreateSBOM(sbom)
		require.NoError(t, err)
	}

	// Test that SBOMs endpoint respects limits
	req := httptest.NewRequest("GET", "/api/v1/sboms", nil)
	resp, err := server.app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var sboms []*models.SBOM
	err = json.Unmarshal(body, &sboms)
	require.NoError(t, err)

	// Should return all 10 SBOMs (within the default limit)
	assert.Len(t, sboms, 10)
}
