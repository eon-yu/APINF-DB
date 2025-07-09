package db

import (
	"fmt"
	"oss-compliance-scanner/models"
	"strings"
	"time"
)

// Report management functions

// CreateReport creates a new report record
func (db *Database) CreateReport(report *models.Report) error {
	err := db.orm.Model(&models.Report{}).Create(report).Error
	if err != nil {
		return fmt.Errorf("failed to create report: %w", err)
	}
	return nil

}

// GetReport retrieves a report by ID
func (db *Database) GetReport(id int) (*models.Report, error) {
	report := &models.Report{}
	err := db.orm.Model(&models.Report{}).Where("id = ?", id).First(&report).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}
	return report, nil
}

// GetAllReports retrieves all reports with pagination
func (db *Database) GetAllReports(limit int) ([]*models.Report, error) {
	reports := []*models.Report{}
	err := db.orm.Model(&models.Report{}).Order("created_at DESC").Limit(limit).Find(&reports).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get reports: %w", err)
	}
	return reports, nil
}

// UpdateReportStatus updates the status of a report
func (db *Database) UpdateReportStatus(id int, status string, filePath string, fileSize int64) error {
	if status == "completed" {
		return db.orm.Model(&models.Report{}).Where("id = ?", id).Updates(map[string]interface{}{
			"status":       status,
			"file_path":    filePath,
			"file_size":    fileSize,
			"completed_at": time.Now(),
		}).Error
	}
	return db.orm.Model(&models.Report{}).Where("id = ?", id).Update("status", status).Error
}

// DeleteReport deletes a report by ID
func (db *Database) DeleteReport(id int) error {
	return db.orm.Model(&models.Report{}).Where("id = ?", id).Delete(&models.Report{}).Error
}

func (db *Database) GetReportData(cfg models.ReportConfig) (*models.ReportData, error) {
	data := &models.ReportData{
		GeneratedAt: time.Now(),
		ScanPeriod:  fmt.Sprintf("%s to %s", cfg.DateFrom, cfg.DateTo),
	}

	// Build dynamic filter for scan_results (aliased as sr)
	q := db.orm.Table("scan_results sr")

	if cfg.DateFrom != "" {
		q = q.Where("scan_start_time >= ?", cfg.DateFrom)
	}
	if cfg.DateTo != "" {
		q = q.Where("scan_start_time <= ?", cfg.DateTo+" 23:59:59")
	}
	if len(cfg.Repositories) > 0 {
		q = q.Where("repo_name IN ?", cfg.Repositories)
	}

	// ----- Total scan count -----
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}
	data.TotalScans = int(total)

	q = q.Select(`OUNT(DISTINCT sr.repo_name) AS total_repositories,
		COUNT(DISTINCT sb.id)       AS total_sboms,
		SUM(sr.total_components)    AS total_components,
		SUM(sr.vulnerabilities_found) AS total_vulns`).Joins("JOIN sboms sb ON sb.id = sr.sbom_id").Where("1=1")
	var summary models.ReportSummary
	if err := q.Scan(&summary).Error; err != nil {
		return nil, err
	}
	data.Summary = summary

	// ----- Repository reports -----
	var repos []models.RepositoryReport
	q = db.orm.Model(&models.ScanResult{}).Select(`
            repo_name,
            COUNT(DISTINCT module_path) AS module_count,
            SUM(total_components)       AS total_components,
            SUM(vulnerabilities_found)  AS total_vulns,
            MAX(scan_end_time)          AS last_scan_date
	`).Group("repo_name").Where("1=1")

	if err := q.Scan(&repos).Error; err != nil {
		return nil, err
	}
	data.Repositories = repos

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
	db.orm.Model(&models.ScanResult{}).Select(`
		COUNT(DISTINCT repo_name) as repo_count,
		COUNT(id) as scan_count,
		COALESCE(SUM(total_components), 0) as component_count,
		COALESCE(SUM(vulnerabilities_found), 0) as vuln_count
	`).Where(whereClause).Scan(&summary)

	// Get vulnerability counts by severity from scan_results
	db.orm.Model(&models.ScanResult{}).Select(`
		COALESCE(SUM(critical_vulns), 0) as critical,
		COALESCE(SUM(high_vulns), 0) as high,
		COALESCE(SUM(medium_vulns), 0) as medium,
		COALESCE(SUM(low_vulns), 0) as low
	`).Where(whereClause).Scan(&summary)

	// Set default language distribution (scan_results doesn't have language info)
	summary.LanguageDistribution["unknown"] = summary.TotalSBOMs

	// Get risk level distribution
	db.orm.Model(&models.ScanResult{}).Select(`
		COALESCE(overall_risk, 'low') as risk_level,
		COUNT(DISTINCT repo_name) as count
	`).Where(strings.ReplaceAll(whereClause, "s.scan_date", "sr.scan_start_time")).Group("overall_risk").Order("count DESC").Scan(&summary.RiskDistribution)

	// Get top vulnerable repositories
	db.orm.Model(&models.ScanResult{}).Select(`
			repo_name,
			COALESCE(SUM(vulnerabilities_found), 0) as total_vulns,
			COALESCE(SUM(critical_vulns), 0) as critical_vulns,
			COALESCE(SUM(high_vulns), 0) as high_vulns,
			COALESCE(SUM(total_components), 0) as component_count,
			MAX(scan_start_time) as last_scan_date
	`).Where(strings.ReplaceAll(whereClause, "s.scan_date", "sr.scan_start_time")).Group("repo_name").Order("total_vulns DESC, critical_vulns DESC, high_vulns DESC").Limit(10).Scan(&summary.TopVulnerableRepos)

	for _, repo := range summary.TopVulnerableRepos {
		var lastScanDateStr string // SQLite 문자열을 받기 위한 임시 변수

		// 문자열을 time.Time으로 파싱
		if repo.LastScanDate != (time.Time{}) {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999-07:00", lastScanDateStr); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05.999999Z07:00", repo.LastScanDate.String()); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05Z", repo.LastScanDate.String()); err == nil {
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
	var repositories []models.RepositoryReport
	db.orm.Model(&models.ScanResult{}).Select(`
			repo_name,
			COUNT(DISTINCT module_path) as module_count,
			COALESCE(SUM(total_components), 0) as total_components,
		COALESCE(SUM(vulnerabilities_found), 0) as total_vulns,
		COALESCE(SUM(critical_vulns), 0) as critical_vulns,
		COALESCE(SUM(high_vulns), 0) as high_vulns,
		COALESCE(SUM(medium_vulns), 0) as medium_vulns,
		COALESCE(SUM(low_vulns), 0) as low_vulns,
		COALESCE(MAX(overall_risk), 'low') as risk_level,
		MAX(scan_start_time) as last_scan_date
	`).Where(whereClause).Group("repo_name").Order("repo_name").Scan(&repositories)

	for _, repo := range repositories {
		var critical, high, medium, low int

		// 문자열을 time.Time으로 파싱
		if repo.LastScanDate != (time.Time{}) {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999-07:00", repo.LastScanDate.String()); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05.999999Z07:00", repo.LastScanDate.String()); err == nil {
				repo.LastScanDate = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02T15:04:05Z", repo.LastScanDate.String()); err == nil {
				repo.LastScanDate = parsedTime
			} else {
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
