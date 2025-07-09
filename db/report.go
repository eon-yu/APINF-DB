package db

import (
	"database/sql"
	"fmt"
	"oss-compliance-scanner/models"
	"strings"
	"time"
)

// Report management functions

// CreateReport creates a new report record
func (db *Database) CreateReport(report *models.Report) error {
	if err := report.MarshalReportFields(); err != nil {
		return fmt.Errorf("failed to marshal report fields: %w", err)
	}

	query := `
		INSERT INTO reports (title, type, status, format, file_path, file_size, 
		                    generated_by, created_at, metadata_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query,
		report.Title, report.Type, report.Status, report.Format,
		report.FilePath, report.FileSize, report.GeneratedBy,
		report.CreatedAt, report.MetadataJSON)
	if err != nil {
		return fmt.Errorf("failed to insert report: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	report.ID = int(id)
	return nil
}

// GetReport retrieves a report by ID
func (db *Database) GetReport(id int) (*models.Report, error) {
	query := `
		SELECT id, title, type, status, format, file_path, file_size,
		       generated_by, created_at, completed_at, metadata_json
		FROM reports
		WHERE id = ?
	`

	report := &models.Report{}
	var completedAt *time.Time

	err := db.conn.QueryRow(query, id).Scan(
		&report.ID, &report.Title, &report.Type, &report.Status,
		&report.Format, &report.FilePath, &report.FileSize,
		&report.GeneratedBy, &report.CreatedAt, &completedAt,
		&report.MetadataJSON,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("report not found with ID %d", id)
		}
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	report.CompletedAt = completedAt

	if err := report.UnmarshalReportFields(); err != nil {
		return nil, fmt.Errorf("failed to unmarshal report fields: %w", err)
	}

	return report, nil
}

// GetAllReports retrieves all reports with pagination
func (db *Database) GetAllReports(limit int) ([]*models.Report, error) {
	query := `
		SELECT id, title, type, status, format, file_path, file_size,
		       generated_by, created_at, completed_at, metadata_json
		FROM reports
		ORDER BY created_at DESC
		LIMIT ?
	`

	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query reports: %w", err)
	}
	defer rows.Close()

	var reports []*models.Report
	for rows.Next() {
		report := &models.Report{}
		var completedAt *time.Time

		err := rows.Scan(
			&report.ID, &report.Title, &report.Type, &report.Status,
			&report.Format, &report.FilePath, &report.FileSize,
			&report.GeneratedBy, &report.CreatedAt, &completedAt,
			&report.MetadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan report: %w", err)
		}

		report.CompletedAt = completedAt

		if err := report.UnmarshalReportFields(); err != nil {
			return nil, fmt.Errorf("failed to unmarshal report fields: %w", err)
		}

		reports = append(reports, report)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating reports: %w", err)
	}

	return reports, nil
}

// UpdateReportStatus updates the status of a report
func (db *Database) UpdateReportStatus(id int, status string, filePath string, fileSize int64) error {
	var query string
	var args []interface{}

	if status == "completed" {
		query = `
			UPDATE reports 
			SET status = ?, file_path = ?, file_size = ?, completed_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`
		args = []interface{}{status, filePath, fileSize, id}
	} else {
		query = `
			UPDATE reports 
			SET status = ?
			WHERE id = ?
		`
		args = []interface{}{status, id}
	}

	result, err := db.conn.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update report status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("report not found with ID %d", id)
	}

	return nil
}

// DeleteReport deletes a report by ID
func (db *Database) DeleteReport(id int) error {
	query := `DELETE FROM reports WHERE id = ?`

	result, err := db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete report: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("report not found with ID %d", id)
	}

	return nil
}

// GetReportData generates report data based on configuration
func (db *Database) GetReportData(config models.ReportConfig) (*models.ReportData, error) {
	data := &models.ReportData{
		GeneratedAt: time.Now(),
		ScanPeriod:  fmt.Sprintf("%s to %s", config.DateFrom, config.DateTo),
	}

	// Build base queries for scan_results table
	whereClause := "1=1"
	args := []interface{}{}

	// Date filtering for scan_results table
	if config.DateFrom != "" {
		whereClause += " AND sr.scan_start_time >= ?"
		args = append(args, config.DateFrom)
	}
	if config.DateTo != "" {
		// Add one day to include the entire end date
		whereClause += " AND sr.scan_start_time <= ?"
		args = append(args, config.DateTo+" 23:59:59")
	}

	// Repository filtering
	if len(config.Repositories) > 0 {
		placeholders := make([]string, len(config.Repositories))
		for i, repo := range config.Repositories {
			placeholders[i] = "?"
			args = append(args, repo)
		}
		whereClause += fmt.Sprintf(" AND sr.repo_name IN (%s)", strings.Join(placeholders, ","))
	}

	// Get summary data
	summary, err := db.getReportSummary(whereClause, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get report summary: %w", err)
	}
	data.Summary = *summary

	// Get repository reports
	repositories, err := db.getRepositoryReports(whereClause, args, config)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository reports: %w", err)
	}
	data.Repositories = repositories

	// Count total scans from scan_results
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM scan_results sr WHERE %s", whereClause)
	err = db.conn.QueryRow(countQuery, args...).Scan(&data.TotalScans)
	if err != nil {
		return nil, fmt.Errorf("failed to count total scans: %w", err)
	}

	return data, nil
}

// getReportSummary generates summary statistics for the report
func (db *Database) getReportSummary(whereClause string, args []interface{}) (*models.ReportSummary, error) {
	summary := &models.ReportSummary{
		VulnsBySeverity:      make(map[string]int),
		LicenseDistribution:  make(map[string]int),
		LanguageDistribution: make(map[string]int),
		RiskDistribution:     make(map[string]int),
	}

	// Get basic counts from scan_results
	basicQuery := fmt.Sprintf(`
		SELECT 
			COUNT(DISTINCT sr.repo_name) as repo_count,
			COUNT(sr.id) as scan_count,
			COALESCE(SUM(sr.total_components), 0) as component_count,
			COALESCE(SUM(sr.vulnerabilities_found), 0) as vuln_count
		FROM scan_results sr 
		WHERE %s`, whereClause)

	err := db.conn.QueryRow(basicQuery, args...).Scan(
		&summary.TotalRepositories,
		&summary.TotalSBOMs,
		&summary.TotalComponents,
		&summary.TotalVulns,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get basic summary: %w", err)
	}

	// Get vulnerability counts by severity from scan_results
	vulnQuery := fmt.Sprintf(`
		SELECT 
			COALESCE(SUM(sr.critical_vulns), 0) as critical,
			COALESCE(SUM(sr.high_vulns), 0) as high,
			COALESCE(SUM(sr.medium_vulns), 0) as medium,
			COALESCE(SUM(sr.low_vulns), 0) as low
		FROM scan_results sr 
		WHERE %s`, whereClause)

	var critical, high, medium, low int
	err = db.conn.QueryRow(vulnQuery, args...).Scan(&critical, &high, &medium, &low)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability severity counts: %w", err)
	}

	summary.VulnsBySeverity["critical"] = critical
	summary.VulnsBySeverity["high"] = high
	summary.VulnsBySeverity["medium"] = medium
	summary.VulnsBySeverity["low"] = low

	// Set default language distribution (scan_results doesn't have language info)
	summary.LanguageDistribution["unknown"] = summary.TotalSBOMs

	// Get risk level distribution
	riskQuery := fmt.Sprintf(`
		SELECT 
			COALESCE(sr.overall_risk, 'low') as risk_level,
			COUNT(DISTINCT sr.repo_name) as count
		FROM scan_results sr 
		WHERE %s
		GROUP BY sr.overall_risk
		ORDER BY count DESC`, strings.ReplaceAll(whereClause, "s.scan_date", "sr.scan_start_time"))

	riskRows, err := db.conn.Query(riskQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get risk distribution: %w", err)
	}
	defer riskRows.Close()

	for riskRows.Next() {
		var riskLevel string
		var count int
		if err := riskRows.Scan(&riskLevel, &count); err != nil {
			return nil, fmt.Errorf("failed to scan risk distribution: %w", err)
		}
		summary.RiskDistribution[riskLevel] = count
	}

	// Get top vulnerable repositories
	topVulnQuery := fmt.Sprintf(`
		SELECT 
			sr.repo_name,
			COALESCE(SUM(sr.vulnerabilities_found), 0) as total_vulns,
			COALESCE(SUM(sr.critical_vulns), 0) as critical_vulns,
			COALESCE(SUM(sr.high_vulns), 0) as high_vulns,
			COALESCE(SUM(sr.total_components), 0) as component_count,
			MAX(sr.scan_start_time) as last_scan_date
		FROM scan_results sr 
		WHERE %s
		GROUP BY sr.repo_name
		ORDER BY total_vulns DESC, critical_vulns DESC, high_vulns DESC
		LIMIT 10`, strings.ReplaceAll(whereClause, "s.scan_date", "sr.scan_start_time"))

	vulnRepoRows, err := db.conn.Query(topVulnQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get top vulnerable repositories: %w", err)
	}
	defer vulnRepoRows.Close()

	for vulnRepoRows.Next() {
		var repo models.VulnerableRepository
		var lastScanDateStr string // SQLite 문자열을 받기 위한 임시 변수

		if err := vulnRepoRows.Scan(
			&repo.RepoName, &repo.TotalVulns, &repo.CriticalVulns,
			&repo.HighVulns, &repo.ComponentCount, &lastScanDateStr,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerable repository: %w", err)
		}

		// 문자열을 time.Time으로 파싱
		if lastScanDateStr != "" {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999-07:00", lastScanDateStr); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05.999999Z07:00", lastScanDateStr); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05Z", lastScanDateStr); err == nil {
				repo.LastScanDate = parsedTime
			} else {
				// 파싱 실패 시 현재 시간으로 기본값 설정
				repo.LastScanDate = time.Now()
			}
		} else {
			repo.LastScanDate = time.Now()
		}

		summary.TopVulnerableRepos = append(summary.TopVulnerableRepos, repo)
	}

	return summary, nil
}

// getRepositoryReports generates detailed reports for each repository
func (db *Database) getRepositoryReports(whereClause string, args []interface{}, config models.ReportConfig) ([]models.RepositoryReport, error) {
	repoQuery := fmt.Sprintf(`
		SELECT 
			sr.repo_name,
			COUNT(DISTINCT sr.module_path) as module_count,
			COALESCE(SUM(sr.total_components), 0) as total_components,
			COALESCE(SUM(sr.vulnerabilities_found), 0) as total_vulns,
			COALESCE(SUM(sr.critical_vulns), 0) as critical_vulns,
			COALESCE(SUM(sr.high_vulns), 0) as high_vulns,
			COALESCE(SUM(sr.medium_vulns), 0) as medium_vulns,
			COALESCE(SUM(sr.low_vulns), 0) as low_vulns,
			COALESCE(MAX(sr.overall_risk), 'low') as risk_level,
			MAX(sr.scan_start_time) as last_scan_date
		FROM scan_results sr 
		WHERE %s
		GROUP BY sr.repo_name
		ORDER BY sr.repo_name`, whereClause)

	rows, err := db.conn.Query(repoQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository reports: %w", err)
	}
	defer rows.Close()

	var repositories []models.RepositoryReport
	for rows.Next() {
		var repo models.RepositoryReport
		var critical, high, medium, low int
		var lastScanDateStr string // SQLite 문자열을 받기 위한 임시 변수

		err := rows.Scan(
			&repo.RepoName, &repo.ModuleCount, &repo.TotalComponents,
			&repo.TotalVulns, &critical, &high, &medium, &low,
			&repo.RiskLevel, &lastScanDateStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan repository report: %w", err)
		}

		// 문자열을 time.Time으로 파싱
		if lastScanDateStr != "" {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999-07:00", lastScanDateStr); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05.999999Z07:00", lastScanDateStr); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05Z", lastScanDateStr); err == nil {
				repo.LastScanDate = parsedTime
			} else {
				// 파싱 실패 시 현재 시간으로 기본값 설정
				repo.LastScanDate = time.Now()
			}
		} else {
			repo.LastScanDate = time.Now()
		}

		repo.VulnsBySeverity = map[string]int{
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
		}

		// Get modules for this repository if detailed report is requested
		if config.IncludeComponents {
			modules, err := db.getModuleReports(repo.RepoName, whereClause, args)
			if err != nil {
				return nil, fmt.Errorf("failed to get modules for repository %s: %w", repo.RepoName, err)
			}
			repo.Modules = modules
		}

		// Get top vulnerabilities for this repository if requested
		if config.IncludeVulns {
			topVulns, err := db.getTopVulnerabilities(repo.RepoName, whereClause, args, 10)
			if err != nil {
				return nil, fmt.Errorf("failed to get top vulnerabilities for repository %s: %w", repo.RepoName, err)
			}
			repo.TopVulns = topVulns
		}

		repositories = append(repositories, repo)
	}

	return repositories, nil
}

// getModuleReports gets detailed module information for a repository
func (db *Database) getModuleReports(repoName string, whereClause string, args []interface{}) ([]models.ModuleReport, error) {
	// Add repository filter to the where clause
	moduleWhereClause := whereClause + " AND sr.repo_name = ?"
	moduleArgs := append(args, repoName)

	moduleQuery := fmt.Sprintf(`
		SELECT 
			sr.module_path,
			'unknown' as language,
			'unknown' as package_manager,
			sr.total_components,
			sr.vulnerabilities_found,
			sr.critical_vulns,
			sr.high_vulns,
			sr.medium_vulns,
			sr.low_vulns,
			COALESCE(sr.overall_risk, 'low') as risk_level,
			sr.scan_start_time
		FROM scan_results sr 
		WHERE %s
		ORDER BY sr.module_path, sr.scan_start_time DESC`, moduleWhereClause)

	rows, err := db.conn.Query(moduleQuery, moduleArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to get module reports: %w", err)
	}
	defer rows.Close()

	var modules []models.ModuleReport
	for rows.Next() {
		var module models.ModuleReport
		var critical, high, medium, low int

		err := rows.Scan(
			&module.ModulePath, &module.Language, &module.PackageManager,
			&module.ComponentCount, &module.VulnCount, &critical, &high,
			&medium, &low, &module.RiskLevel, &module.ScanDate,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan module report: %w", err)
		}

		module.VulnsBySeverity = map[string]int{
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
		}

		modules = append(modules, module)
	}

	return modules, nil
}
