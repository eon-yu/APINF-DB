package db

import (
	"fmt"
	"oss-compliance-scanner/models"
)

// CreateScanResult creates a new scan result record
func (db *Database) CreateScanResult(result *models.ScanResult) error {
	// Marshal JSON fields
	if err := result.MarshalScanResultFields(); err != nil {
		return fmt.Errorf("failed to marshal scan result fields: %w", err)
	}

	query := `
		INSERT INTO scan_results (sbom_id, repo_name, module_path, scan_start_time, scan_end_time,
		                         status, total_components, vulnerabilities_found, license_violations,
		                         critical_vulns, high_vulns, medium_vulns, low_vulns, overall_risk,
		                         metadata_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	execResult, err := db.conn.Exec(query, result.SBOMID, result.RepoName, result.ModulePath,
		result.ScanStartTime, result.ScanEndTime, result.Status, result.TotalComponents,
		result.VulnerabilitiesFound, result.LicenseViolations, result.CriticalVulns,
		result.HighVulns, result.MediumVulns, result.LowVulns, result.OverallRisk,
		result.MetadataJSON)
	if err != nil {
		return fmt.Errorf("failed to create scan result: %w", err)
	}

	id, err := execResult.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get scan result ID: %w", err)
	}

	result.ID = int(id)
	return nil
}

// GetLatestScanResults retrieves the latest scan results for all repos/modules
func (db *Database) GetLatestScanResults(limit int) ([]*models.ScanResult, error) {
	query := `
		SELECT id, sbom_id, repo_name, module_path, scan_start_time, scan_end_time,
		       status, total_components, vulnerabilities_found, license_violations,
		       critical_vulns, high_vulns, medium_vulns, low_vulns, overall_risk,
		       metadata_json, created_at, updated_at
		FROM scan_results
		ORDER BY scan_start_time DESC
		LIMIT ?
	`

	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query scan results: %w", err)
	}
	defer rows.Close()

	var results []*models.ScanResult
	for rows.Next() {
		result := &models.ScanResult{}
		err := rows.Scan(
			&result.ID, &result.SBOMID, &result.RepoName, &result.ModulePath,
			&result.ScanStartTime, &result.ScanEndTime, &result.Status,
			&result.TotalComponents, &result.VulnerabilitiesFound, &result.LicenseViolations,
			&result.CriticalVulns, &result.HighVulns, &result.MediumVulns, &result.LowVulns,
			&result.OverallRisk, &result.MetadataJSON, &result.CreatedAt, &result.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan scan result: %w", err)
		}

		// Unmarshal JSON fields
		if err := result.UnmarshalScanResultFields(); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scan result fields: %w", err)
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating scan results: %w", err)
	}

	return results, nil
}
