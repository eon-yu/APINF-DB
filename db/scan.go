package db

import (
	"fmt"
	"oss-compliance-scanner/models"
)

// CreateScanResult creates a new scan result record
func (db *Database) CreateScanResult(result *models.ScanResult) error {
	err := db.orm.Model(&models.ScanResult{}).Create(result).Error
	if err != nil {
		return fmt.Errorf("failed to create scan result: %w", err)
	}

	return nil

}

// GetLatestScanResults retrieves the latest scan results for all repos/modules
func (db *Database) GetLatestScanResults(limit int) ([]*models.ScanResult, error) {
	var results []*models.ScanResult
	err := db.orm.Model(&models.ScanResult{}).Order("scan_start_time DESC").Limit(limit).Find(&results).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get latest scan results: %w", err)
	}
	return results, nil
}
