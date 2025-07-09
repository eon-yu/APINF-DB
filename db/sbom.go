package db

import (
	"errors"
	"fmt"
	"oss-compliance-scanner/models"

	"gorm.io/gorm"
)

// CreateSBOM creates a new SBOM record
func (db *Database) CreateSBOM(sbom *models.SBOM) error {
	return db.orm.Model(&models.SBOM{}).Create(&sbom).Error
}

// GetSBOM retrieves an SBOM by ID
func (db *Database) GetSBOM(id int) (*models.SBOM, error) {
	sbom := &models.SBOM{}
	err := db.orm.Where("id = ?", id).First(&sbom).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("SBOM not found with ID %d", id)
		}
		return nil, fmt.Errorf("failed to get SBOM: %w", err)
	}

	return sbom, nil
}

// GetLatestSBOM retrieves the latest SBOM for a repo/module
func (db *Database) GetLatestSBOM(repoName, modulePath string) (*models.SBOM, error) {
	sbom := &models.SBOM{}
	err := db.orm.Where("repo_name = ? AND module_path = ?", repoName, modulePath).Order("scan_date DESC").First(&sbom).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("no SBOM found for %s/%s", repoName, modulePath)
		}
		return nil, fmt.Errorf("failed to get latest SBOM: %w", err)
	}

	return sbom, nil
}

// GetAllSBOMs retrieves all SBOMs with limit
func (db *Database) GetAllSBOMs(limit int) ([]*models.SBOM, error) {
	var sboms []*models.SBOM
	err := db.orm.Order("scan_date DESC").Limit(limit).Find(&sboms).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get all SBOMs: %w", err)
	}
	return sboms, nil
}

// CreateComponent creates a new component record with improved license parsing
func (db *Database) CreateComponent(component *models.Component) error {
	// If we have raw license data, improve the parsing before marshaling
	if component.LicensesJSON != "" && len(component.Licenses) == 0 {
		// Create a temporary SyftArtifact to use the improved parsing
		tempArtifact := &models.SyftArtifact{
			LicensesRaw: []byte(component.LicensesJSON),
		}
		component.Licenses = tempArtifact.UnmarshalLicenses()
	}

	// Marshal JSON fields
	if err := component.MarshalComponentFields(); err != nil {
		return fmt.Errorf("failed to marshal component fields: %w", err)
	}
	db.orm.Create(&component)
	return nil
}

// GetComponentsBySBOM retrieves all components for an SBOM
func (db *Database) GetComponentsBySBOM(sbomID int) ([]*models.Component, error) {
	var components []*models.Component
	err := db.orm.Where("sbom_id = ?", sbomID).Order("name, version").Find(&components).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get components: %w", err)
	}
	return components, nil
}

// GetComponent retrieves a specific component by ID
func (db *Database) GetComponent(componentID int) (*models.Component, error) {
	component := &models.Component{}
	err := db.orm.Where("id = ?", componentID).First(&component).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("component not found with ID %d", componentID)
		}
		return nil, fmt.Errorf("failed to get component: %w", err)
	}

	return component, nil
}

// UpdateSBOMComponentCount updates the component_count field for an SBOM
func (db *Database) UpdateSBOMComponentCount(sbomID, componentCount int) error {
	db.orm.Model(&models.SBOM{}).Where("id = ?", sbomID).Update("component_count", componentCount)
	return nil
}

// DeleteSBOM deletes an SBOM and all its related data (components, vulnerabilities)
func (db *Database) DeleteSBOM(sbomID int) error {
	db.orm.Where("id = ?", sbomID).Delete(&models.SBOM{})
	return nil
}

// DeleteSBOMs deletes multiple SBOMs and all their related data
func (db *Database) DeleteSBOMs(sbomIDs []int) error {
	if len(sbomIDs) == 0 {
		return nil
	}

	db.orm.Where("id IN (?)", sbomIDs).Delete(&models.SBOM{})
	return nil
}

// DeleteRepository deletes all SBOMs and related data for a repository

// GetSBOMsByRepository returns all SBOMs for a given repository
func (db *Database) GetSBOMsByRepository(repoName string) ([]*models.SBOM, error) {
	var sboms []*models.SBOM
	err := db.orm.Where("repo_name = ?", repoName).Order("module_path, scan_date DESC").Find(&sboms).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get SBOMs: %w", err)
	}
	return sboms, nil
}

// DeleteRepository deletes all SBOMs and related data for a repository
func (db *Database) DeleteRepository(repoName string) error {
	// First, get all SBOM IDs for this repository
	var sbomIDs []int
	err := db.orm.Model(&models.SBOM{}).Where("repo_name = ?", repoName).Pluck("id", &sbomIDs).Error
	if err != nil {
		return fmt.Errorf("failed to get SBOM IDs for repository: %w", err)
	}

	return db.DeleteSBOMs(sbomIDs)
}
