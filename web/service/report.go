package service

import (
	"fmt"
	"log"
	"os"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

type ReportService struct {
	database *db.Database
}

func NewReportService(db *db.Database) *ReportService {
	return &ReportService{database: db}
}

// Report API handlers

// handleAPIReports returns all reports
func (ds *ReportService) HandleAPIReports(c *fiber.Ctx) error {
	reports, err := ds.database.GetAllReports(100)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch reports"})
	}

	return c.JSON(reports)
}

// handleAPICreateReport creates a new report
func (ds *ReportService) HandleAPICreateReport(c *fiber.Ctx) error {
	var req models.ReportConfig
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Validate required fields
	if req.DateFrom == "" || req.DateTo == "" {
		return c.Status(400).JSON(fiber.Map{"error": "date_from and date_to are required"})
	}

	// Create report record
	report := &models.Report{
		Title:        fmt.Sprintf("Scan Report - %s to %s", req.DateFrom, req.DateTo),
		Type:         "pdf", // Default to PDF
		Status:       "generating",
		Format:       "summary", // Default format
		GeneratedBy:  "system",  // In production, get from user context
		CreatedAt:    time.Now(),
		ReportConfig: req,
		Metadata:     make(map[string]any),
	}

	// Save report to database
	if err := ds.database.CreateReport(report); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create report"})
	}

	// Start background report generation
	go ds.generateReport(report.ID, req)

	return c.JSON(fiber.Map{
		"report_id": report.ID,
		"status":    "generating",
		"message":   "Report generation started",
	})
}

// handleAPIReportDetail returns details of a specific report
func (ds *ReportService) HandleAPIReportDetail(c *fiber.Ctx) error {
	idParam := c.Params("id")
	reportID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid report ID"})
	}

	report, err := ds.database.GetReport(reportID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Report not found"})
	}

	return c.JSON(report)
}

// handleAPIReportDownload downloads a generated report
func (ds *ReportService) HandleAPIReportDownload(c *fiber.Ctx) error {
	id := c.Params("id")
	reportID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error": "Invalid report ID",
		})
	}

	report, err := ds.database.GetReport(reportID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error": "Report not found",
		})
	}

	if report.Status != "completed" {
		return c.Status(400).JSON(fiber.Map{
			"error": "Report is not ready for download",
		})
	}

	// Get the actual content type based on file extension
	contentType := "application/octet-stream"
	if strings.HasSuffix(report.FilePath, ".pdf") {
		contentType = "application/pdf"
	} else if strings.HasSuffix(report.FilePath, ".csv") {
		contentType = "text/csv"
	} else if strings.HasSuffix(report.FilePath, ".xlsx") {
		contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}

	// Set appropriate headers
	c.Set("Content-Type", contentType)
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		filepath.Base(report.FilePath)))

	return c.SendFile(report.FilePath)
}

// handleAPIDeleteReport deletes a report
func (ds *ReportService) HandleAPIDeleteReport(c *fiber.Ctx) error {
	idParam := c.Params("id")
	reportID, err := strconv.Atoi(idParam)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid report ID"})
	}

	// Get report to check if file exists
	report, err := ds.database.GetReport(reportID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Report not found"})
	}

	// Delete file if it exists
	if report.FilePath != "" {
		if _, err := os.Stat(report.FilePath); err == nil {
			os.Remove(report.FilePath)
		}
	}

	// Delete from database
	if err := ds.database.DeleteReport(reportID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to delete report"})
	}

	return c.Status(204).Send(nil)
}

// Helper functions for report generation

func (ds *ReportService) generateReport(reportID int, config models.ReportConfig) {
	log.Printf("보고서 생성 시작: ID=%d, Config=%+v", reportID, config)

	// Update status to generating
	if err := ds.database.UpdateReportStatus(reportID, "generating", "", 0); err != nil {
		log.Printf("보고서 상태 업데이트 실패 (generating): %v", err)
		return
	}

	// Get report data
	log.Printf("보고서 데이터 수집 중...")
	reportData, err := ds.database.GetReportData(config)
	if err != nil {
		log.Printf("보고서 데이터 수집 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	log.Printf("보고서 데이터 수집 완료: 저장소 %d개, SBOM %d개, 컴포넌트 %d개",
		reportData.Summary.TotalRepositories, reportData.Summary.TotalSBOMs, reportData.Summary.TotalComponents)

	// Create reports directory if it doesn't exist
	reportsDir := "./reports"
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		log.Printf("보고서 디렉토리 생성 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	// Generate file based on report type
	timestamp := time.Now().Format("20060102_150405")
	var filename, filePath string

	// Get the actual report type from the request, default to 'pdf'
	reportType := config.ReportType
	if reportType == "" {
		reportType = "pdf"
	}

	switch reportType {
	case "csv":
		filename = fmt.Sprintf("scan_report_%s_%d.csv", timestamp, reportID)
		filePath = filepath.Join(reportsDir, filename)
		err = ds.generateCSVReport(reportData, filePath)
	case "excel":
		filename = fmt.Sprintf("scan_report_%s_%d.xlsx", timestamp, reportID)
		filePath = filepath.Join(reportsDir, filename)
		err = ds.generateExcelReport(reportData, filePath)
	default: // pdf
		filename = fmt.Sprintf("scan_report_%s_%d.pdf", timestamp, reportID)
		filePath = filepath.Join(reportsDir, filename)
		err = ds.generatePDFReport(reportData, filePath)
	}

	if err != nil {
		log.Printf("보고서 파일 생성 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	// Get file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("보고서 파일 정보 확인 실패: %v", err)
		ds.database.UpdateReportStatus(reportID, "failed", "", 0)
		return
	}

	log.Printf("보고서 생성 완료: %s (크기: %d bytes)", filePath, fileInfo.Size())

	// Update status to completed
	if err := ds.database.UpdateReportStatus(reportID, "completed", filePath, fileInfo.Size()); err != nil {
		log.Printf("보고서 상태 업데이트 실패 (completed): %v", err)
		return
	}

	log.Printf("보고서 ID %d 생성 완료", reportID)
}

func (ds *ReportService) generatePDFReport(data *models.ReportData, filePath string) error {
	// Create a proper text-based report that can be read as a document
	content := ds.generateTextReport(data)

	// For now, we'll create a formatted text file with .pdf extension
	// In production, you would use a proper PDF library like gofpdf or wkhtmltopdf

	// Add proper document structure
	documentContent := fmt.Sprintf(`%%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length %d
>>
stream
BT
/F1 12 Tf
72 720 Td
(%s) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000010 00000 n 
0000000079 00000 n 
0000000136 00000 n 
0000000217 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
%d
%%%%EOF`, len(content), content, 300+len(content))

	return os.WriteFile(filePath, []byte(documentContent), 0644)
}

func (ds *ReportService) generateCSVReport(data *models.ReportData, filePath string) error {
	var csvContent strings.Builder

	// Add BOM for proper UTF-8 encoding in Excel
	csvContent.WriteString("\uFEFF")

	// Header
	csvContent.WriteString("Repository,Module Count,Components,Vulnerabilities,Critical,High,Medium,Low,Risk Level,Last Scan\n")

	// Data rows - show repository summary data
	for _, repo := range data.Repositories {
		csvContent.WriteString(fmt.Sprintf("%s,%d,%d,%d,%d,%d,%d,%d,%s,%s\n",
			escapeCsv(repo.RepoName),
			repo.ModuleCount,
			repo.TotalComponents,
			repo.TotalVulns,
			repo.VulnsBySeverity["critical"],
			repo.VulnsBySeverity["high"],
			repo.VulnsBySeverity["medium"],
			repo.VulnsBySeverity["low"],
			escapeCsv(repo.RiskLevel),
			repo.LastScanDate.Format("2006-01-02 15:04:05"),
		))
	}

	return os.WriteFile(filePath, []byte(csvContent.String()), 0644)
}

func (ds *ReportService) generateExcelReport(data *models.ReportData, filePath string) error {
	// For now, generate CSV format with .xlsx extension
	// In production, use a proper Excel library like excelize
	return ds.generateCSVReport(data, filePath)
}

// Helper function to escape CSV values
func escapeCsv(value string) string {
	if strings.Contains(value, ",") || strings.Contains(value, "\"") || strings.Contains(value, "\n") {
		value = strings.ReplaceAll(value, "\"", "\"\"")
		return "\"" + value + "\""
	}
	return value
}

func (ds *ReportService) generateTextReport(data *models.ReportData) string {
	var report strings.Builder

	report.WriteString("OSS COMPLIANCE SCAN REPORT\n")
	report.WriteString("=========================\n\n")
	report.WriteString(fmt.Sprintf("Generated: %s\n", data.GeneratedAt.Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("Scan Period: %s\n", data.ScanPeriod))
	report.WriteString(fmt.Sprintf("Total Scans: %d\n\n", data.TotalScans))

	// Summary section
	report.WriteString("EXECUTIVE SUMMARY\n")
	report.WriteString("-----------------\n")
	report.WriteString(fmt.Sprintf("Total Repositories: %d\n", data.Summary.TotalRepositories))
	report.WriteString(fmt.Sprintf("Total SBOMs: %d\n", data.Summary.TotalSBOMs))
	report.WriteString(fmt.Sprintf("Total Components: %d\n", data.Summary.TotalComponents))
	report.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n\n", data.Summary.TotalVulns))

	// Vulnerability breakdown
	report.WriteString("VULNERABILITY BREAKDOWN\n")
	report.WriteString("-----------------------\n")
	for severity, count := range data.Summary.VulnsBySeverity {
		report.WriteString(fmt.Sprintf("%s: %d\n", strings.Title(severity), count))
	}
	report.WriteString("\n")

	// Language distribution
	if len(data.Summary.LanguageDistribution) > 0 {
		report.WriteString("LANGUAGE DISTRIBUTION\n")
		report.WriteString("--------------------\n")
		for language, count := range data.Summary.LanguageDistribution {
			report.WriteString(fmt.Sprintf("%s: %d projects\n", language, count))
		}
		report.WriteString("\n")
	}

	// Top vulnerable repositories
	if len(data.Summary.TopVulnerableRepos) > 0 {
		report.WriteString("TOP VULNERABLE REPOSITORIES\n")
		report.WriteString("---------------------------\n")
		for i, repo := range data.Summary.TopVulnerableRepos {
			if i >= 5 {
				break
			} // Top 5
			report.WriteString(fmt.Sprintf("%d. %s - %d vulnerabilities (%d critical, %d high)\n",
				i+1, repo.RepoName, repo.TotalVulns, repo.CriticalVulns, repo.HighVulns))
		}
		report.WriteString("\n")
	}

	// Repository details
	report.WriteString("REPOSITORY DETAILS\n")
	report.WriteString("------------------\n")
	for _, repo := range data.Repositories {
		report.WriteString(fmt.Sprintf("\nRepository: %s\n", repo.RepoName))
		report.WriteString(fmt.Sprintf("  Modules: %d\n", repo.ModuleCount))
		report.WriteString(fmt.Sprintf("  Components: %d\n", repo.TotalComponents))
		report.WriteString(fmt.Sprintf("  Vulnerabilities: %d\n", repo.TotalVulns))
		report.WriteString(fmt.Sprintf("  Risk Level: %s\n", repo.RiskLevel))
		report.WriteString(fmt.Sprintf("  Last Scan: %s\n", repo.LastScanDate.Format("2006-01-02 15:04")))
	}

	return report.String()
}

func getContentType(reportType string) string {
	switch reportType {
	case "pdf":
		return "application/pdf"
	case "csv":
		return "text/csv"
	case "excel":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	default:
		return "application/octet-stream"
	}
}
