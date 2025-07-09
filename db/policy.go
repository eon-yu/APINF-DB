package db

import (
	"fmt"
	"oss-compliance-scanner/models"
)

// Policy Operations

// CreateLicensePolicy creates a new license policy
func (db *Database) CreateLicensePolicy(policy *models.LicensePolicy) error {
	err := db.orm.Model(&models.LicensePolicy{}).Create(policy).Error
	if err != nil {
		return fmt.Errorf("failed to create license policy: %w", err)
	}
	return nil
}

// GetActiveLicensePolicies retrieves all active license policies
func (db *Database) GetActiveLicensePolicies() ([]*models.LicensePolicy, error) {
	var policies []*models.LicensePolicy
	err := db.orm.Model(&models.LicensePolicy{}).Where("is_active = ?", true).Order("license_name").Find(&policies).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get active license policies: %w", err)
	}
	return policies, nil
}

// CreateVulnerabilityPolicy creates a new vulnerability policy
func (db *Database) CreateVulnerabilityPolicy(policy *models.VulnerabilityPolicy) error {
	err := db.orm.Model(&models.VulnerabilityPolicy{}).Create(policy).Error
	if err != nil {
		return fmt.Errorf("failed to create vulnerability policy: %w", err)
	}
	return nil
}

// GetActiveVulnerabilityPolicies retrieves all active vulnerability policies
func (db *Database) GetActiveVulnerabilityPolicies() ([]*models.VulnerabilityPolicy, error) {
	var policies []*models.VulnerabilityPolicy
	err := db.orm.Model(&models.VulnerabilityPolicy{}).Where("is_active = ?", true).Order("max_cvss_score DESC").Find(&policies).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get active vulnerability policies: %w", err)
	}
	return policies, nil
}

// DeleteLicensePolicy deletes a license policy by ID
func (db *Database) DeleteLicensePolicy(id int) error {
	err := db.orm.Model(&models.LicensePolicy{}).Where("id = ?", id).Delete(&models.LicensePolicy{}).Error
	if err != nil {
		return fmt.Errorf("failed to delete license policy: %w", err)
	}
	return nil
}

// DeleteVulnerabilityPolicy deletes a vulnerability policy by ID
func (db *Database) DeleteVulnerabilityPolicy(id int) error {
	err := db.orm.Model(&models.VulnerabilityPolicy{}).Where("id = ?", id).Delete(&models.VulnerabilityPolicy{}).Error
	if err != nil {
		return fmt.Errorf("failed to delete vulnerability policy: %w", err)
	}
	return nil
}
