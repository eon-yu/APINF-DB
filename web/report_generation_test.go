package web

import (
	"bytes"
	"encoding/json"
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

func setupSimpleReportTestServer(t *testing.T) (*DashboardServer, func()) {
	tempDir, err := os.MkdirTemp("", "simple_report_test_*")
	require.NoError(t, err)

	dbPath := filepath.Join(tempDir, "test.db")
	database, err := db.NewDatabase("sqlite3", dbPath)
	require.NoError(t, err)

	// Run migrations to create all tables
	err = database.RunMigrations()
	require.NoError(t, err)

	server := NewDashboardServer(database, "8080")
	server.setupRoutes()

	cleanup := func() {
		database.Close()
		os.RemoveAll(tempDir)
	}

	return server, cleanup
}

func TestBasicReportAPI(t *testing.T) {
	server, cleanup := setupSimpleReportTestServer(t)
	defer cleanup()

	t.Run("Get Empty Reports List", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/reports", nil)
		resp, err := server.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var reports []models.Report
		err = json.NewDecoder(resp.Body).Decode(&reports)
		require.NoError(t, err)
		assert.Equal(t, 0, len(reports))
	})

	t.Run("Create Report - Missing Fields", func(t *testing.T) {
		invalidConfig := map[string]interface{}{
			"date_from": "",
			"date_to":   "",
		}

		reqBody, err := json.Marshal(invalidConfig)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/reports", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := server.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 400, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Contains(t, result, "error")
	})

	t.Run("Create Valid Report", func(t *testing.T) {
		reportConfig := models.ReportConfig{
			DateFrom:          "2023-01-01",
			DateTo:            "2023-12-31",
			Repositories:      []string{},
			IncludeVulns:      true,
			IncludeLicense:    true,
			IncludeComponents: false,
			IncludeCharts:     false,
			SeverityFilter:    "",
		}

		reqBody, err := json.Marshal(reportConfig)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/reports", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := server.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)

		assert.Contains(t, result, "report_id")
		assert.Equal(t, "generating", result["status"])
		assert.Contains(t, result, "message")

		// Give some time for background generation
		time.Sleep(100 * time.Millisecond)

		// Check that report was created
		reportID := int(result["report_id"].(float64))
		req = httptest.NewRequest("GET", "/api/v1/reports", nil)
		resp, err = server.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)

		var reports []models.Report
		err = json.NewDecoder(resp.Body).Decode(&reports)
		require.NoError(t, err)
		assert.Greater(t, len(reports), 0)

		// Find our report
		var foundReport *models.Report
		for _, report := range reports {
			if report.ID == reportID {
				foundReport = &report
				break
			}
		}
		require.NotNil(t, foundReport, "Created report should be in the list")
		assert.Equal(t, "pdf", foundReport.Type)
		assert.Contains(t, []string{"generating", "completed", "failed"}, foundReport.Status)
	})

	t.Run("Get Non-existent Report", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/reports/99999", nil)
		resp, err := server.Test(req)
		require.NoError(t, err)
		assert.Equal(t, 404, resp.StatusCode)
	})
}

func TestReportHelperFunctions(t *testing.T) {
	t.Run("Content Type Helper", func(t *testing.T) {
		assert.Equal(t, "application/pdf", getContentType("pdf"))
		assert.Equal(t, "text/csv", getContentType("csv"))
		assert.Equal(t, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", getContentType("excel"))
		assert.Equal(t, "application/octet-stream", getContentType("unknown"))
	})
}

func TestReportGeneration(t *testing.T) {
	server, cleanup := setupSimpleReportTestServer(t)
	defer cleanup()

	t.Run("Test Report Data Structure", func(t *testing.T) {
		// Create a basic report data structure
		reportData := &models.ReportData{
			GeneratedAt: time.Now(),
			ScanPeriod:  "2023-01-01 to 2023-12-31",
			TotalScans:  0,
			Summary: models.ReportSummary{
				TotalRepositories: 0,
				TotalSBOMs:        0,
				TotalComponents:   0,
				TotalVulns:        0,
				VulnsBySeverity: map[string]int{
					"critical": 0,
					"high":     0,
					"medium":   0,
					"low":      0,
				},
				LanguageDistribution: map[string]int{},
				RiskDistribution:     map[string]int{},
				TopVulnerableRepos:   []models.VulnerableRepository{},
			},
			Repositories: []models.RepositoryReport{},
		}

		assert.NotNil(t, reportData)
		assert.NotNil(t, reportData.Summary)
		assert.Equal(t, 0, reportData.Summary.TotalRepositories)
	})

	t.Run("Test PDF Generation", func(t *testing.T) {
		// Create temp directory for test file
		tempDir, err := os.MkdirTemp("", "pdf_test_*")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		filePath := filepath.Join(tempDir, "test_report.pdf")

		// Create sample report data
		reportData := &models.ReportData{
			GeneratedAt: time.Now(),
			ScanPeriod:  "2023-01-01 to 2023-12-31",
			TotalScans:  1,
			Summary: models.ReportSummary{
				TotalRepositories: 1,
				TotalSBOMs:        1,
				TotalComponents:   100,
				TotalVulns:        10,
				VulnsBySeverity: map[string]int{
					"critical": 2,
					"high":     3,
					"medium":   3,
					"low":      2,
				},
				LanguageDistribution: map[string]int{
					"javascript": 1,
				},
				RiskDistribution: map[string]int{
					"medium": 1,
				},
				TopVulnerableRepos: []models.VulnerableRepository{},
			},
			Repositories: []models.RepositoryReport{},
		}

		// Test PDF generation
		err = server.generatePDFReport(reportData, filePath)
		require.NoError(t, err)

		// Check that file was created
		assert.FileExists(t, filePath)

		// Check file content
		content, err := os.ReadFile(filePath)
		require.NoError(t, err)
		assert.Contains(t, string(content), "OSS COMPLIANCE SCAN REPORT")
		assert.Contains(t, string(content), "EXECUTIVE SUMMARY")
		assert.Contains(t, string(content), "Total Repositories: 1")
		assert.Contains(t, string(content), "Total Components: 100")
		assert.Contains(t, string(content), "Total Vulnerabilities: 10")
	})
}
