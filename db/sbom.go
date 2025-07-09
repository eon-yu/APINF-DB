package db

import (
	"database/sql"
	"fmt"
	"oss-compliance-scanner/models"
)

// CreateSBOM creates a new SBOM record
func (db *Database) CreateSBOM(sbom *models.SBOM) error {
	query := `
		INSERT INTO sboms (repo_name, module_path, scan_date, syft_version, raw_sbom, component_count)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query, sbom.RepoName, sbom.ModulePath, sbom.ScanDate,
		sbom.SyftVersion, sbom.RawSBOM, sbom.ComponentCount)
	if err != nil {
		return fmt.Errorf("failed to create SBOM: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get SBOM ID: %w", err)
	}

	sbom.ID = int(id)
	return nil
}

// GetSBOM retrieves an SBOM by ID
func (db *Database) GetSBOM(id int) (*models.SBOM, error) {
	query := `
		SELECT id, repo_name, module_path, scan_date, syft_version, raw_sbom,
		       component_count, created_at, updated_at
		FROM sboms WHERE id = ?
	`

	sbom := &models.SBOM{}
	err := db.conn.QueryRow(query, id).Scan(
		&sbom.ID, &sbom.RepoName, &sbom.ModulePath, &sbom.ScanDate,
		&sbom.SyftVersion, &sbom.RawSBOM, &sbom.ComponentCount,
		&sbom.CreatedAt, &sbom.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("SBOM not found with ID %d", id)
		}
		return nil, fmt.Errorf("failed to get SBOM: %w", err)
	}

	return sbom, nil
}

// GetLatestSBOM retrieves the latest SBOM for a repo/module
func (db *Database) GetLatestSBOM(repoName, modulePath string) (*models.SBOM, error) {
	query := `
		SELECT id, repo_name, module_path, scan_date, syft_version, raw_sbom,
		       component_count, created_at, updated_at
		FROM sboms
		WHERE repo_name = ? AND module_path = ?
		ORDER BY scan_date DESC
		LIMIT 1
	`

	sbom := &models.SBOM{}
	err := db.conn.QueryRow(query, repoName, modulePath).Scan(
		&sbom.ID, &sbom.RepoName, &sbom.ModulePath, &sbom.ScanDate,
		&sbom.SyftVersion, &sbom.RawSBOM, &sbom.ComponentCount,
		&sbom.CreatedAt, &sbom.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no SBOM found for %s/%s", repoName, modulePath)
		}
		return nil, fmt.Errorf("failed to get latest SBOM: %w", err)
	}

	return sbom, nil
}

// GetAllSBOMs retrieves all SBOMs with limit
func (db *Database) GetAllSBOMs(limit int) ([]*models.SBOM, error) {
	query := `
		SELECT id, repo_name, module_path, scan_date, syft_version, raw_sbom,
		       component_count, created_at, updated_at
		FROM sboms
		ORDER BY scan_date DESC
		LIMIT ?
	`

	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query SBOMs: %w", err)
	}
	defer rows.Close()

	var sboms []*models.SBOM
	for rows.Next() {
		sbom := &models.SBOM{}
		err := rows.Scan(
			&sbom.ID, &sbom.RepoName, &sbom.ModulePath, &sbom.ScanDate,
			&sbom.SyftVersion, &sbom.RawSBOM, &sbom.ComponentCount,
			&sbom.CreatedAt, &sbom.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SBOM: %w", err)
		}
		sboms = append(sboms, sbom)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating SBOMs: %w", err)
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

	query := `
		INSERT INTO components (sbom_id, name, version, type, purl, cpe, language,
		                       licenses_json, locations_json, metadata_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query, component.SBOMID, component.Name, component.Version,
		component.Type, component.PURL, component.CPE, component.Language,
		component.LicensesJSON, component.LocationsJSON, component.MetadataJSON)
	if err != nil {
		return fmt.Errorf("failed to create component: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get component ID: %w", err)
	}

	component.ID = int(id)

	// Update SBOM component count
	if err := db.UpdateSBOMComponentCount(component.SBOMID); err != nil {
		// Log error but don't fail the component creation
		fmt.Printf("Warning: failed to update SBOM component count: %v\n", err)
	}

	return nil
}

// GetComponentsBySBOM retrieves all components for an SBOM
func (db *Database) GetComponentsBySBOM(sbomID int) ([]*models.Component, error) {
	query := `
		SELECT id, sbom_id, name, version, type, purl, cpe, language,
		       licenses_json, locations_json, metadata_json, created_at, updated_at
		FROM components WHERE sbom_id = ?
		ORDER BY name, version
	`

	rows, err := db.conn.Query(query, sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query components: %w", err)
	}
	defer rows.Close()

	var components []*models.Component
	for rows.Next() {
		component := &models.Component{}
		err := rows.Scan(
			&component.ID, &component.SBOMID, &component.Name, &component.Version,
			&component.Type, &component.PURL, &component.CPE, &component.Language,
			&component.LicensesJSON, &component.LocationsJSON, &component.MetadataJSON,
			&component.CreatedAt, &component.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan component: %w", err)
		}

		// Unmarshal JSON fields
		if err := component.UnmarshalComponentFields(); err != nil {
			return nil, fmt.Errorf("failed to unmarshal component fields: %w", err)
		}

		components = append(components, component)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating components: %w", err)
	}

	return components, nil
}

// GetComponent retrieves a specific component by ID
func (db *Database) GetComponent(componentID int) (*models.Component, error) {
	query := `
		SELECT id, sbom_id, name, version, type, purl, cpe, language,
		       licenses_json, locations_json, metadata_json, created_at, updated_at
		FROM components WHERE id = ?
	`

	row := db.conn.QueryRow(query, componentID)

	component := &models.Component{}
	err := row.Scan(
		&component.ID, &component.SBOMID, &component.Name, &component.Version,
		&component.Type, &component.PURL, &component.CPE, &component.Language,
		&component.LicensesJSON, &component.LocationsJSON, &component.MetadataJSON,
		&component.CreatedAt, &component.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("component not found")
		}
		return nil, fmt.Errorf("failed to get component: %w", err)
	}

	// Unmarshal JSON fields
	if err := component.UnmarshalComponentFields(); err != nil {
		return nil, fmt.Errorf("failed to unmarshal component fields: %w", err)
	}

	return component, nil
}

// UpdateSBOMComponentCount updates the component_count field for an SBOM
func (db *Database) UpdateSBOMComponentCount(sbomID int) error {
	query := `
		UPDATE sboms
		SET component_count = (
			SELECT COUNT(*) FROM components WHERE sbom_id = ?
		),
		updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`

	_, err := db.conn.Exec(query, sbomID, sbomID)
	if err != nil {
		return fmt.Errorf("failed to update SBOM component count: %w", err)
	}

	return nil
}

// DeleteSBOM deletes an SBOM and all its related data (components, vulnerabilities)
func (db *Database) DeleteSBOM(sbomID int) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete vulnerabilities for all components of this SBOM
	_, err = tx.Exec(`
		DELETE FROM vulnerabilities 
		WHERE component_id IN (
			SELECT id FROM components WHERE sbom_id = ?
		)
	`, sbomID)
	if err != nil {
		return fmt.Errorf("failed to delete vulnerabilities: %w", err)
	}

	// Delete components
	_, err = tx.Exec("DELETE FROM components WHERE sbom_id = ?", sbomID)
	if err != nil {
		return fmt.Errorf("failed to delete components: %w", err)
	}

	// Delete SBOM
	_, err = tx.Exec("DELETE FROM sboms WHERE id = ?", sbomID)
	if err != nil {
		return fmt.Errorf("failed to delete SBOM: %w", err)
	}

	return tx.Commit()
}

// DeleteSBOMs deletes multiple SBOMs and all their related data
func (db *Database) DeleteSBOMs(sbomIDs []int) error {
	if len(sbomIDs) == 0 {
		return nil
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Create placeholder string for IN clause
	placeholders := ""
	args := make([]interface{}, len(sbomIDs))
	for i, id := range sbomIDs {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args[i] = id
	}

	// Delete vulnerabilities for all components of these SBOMs
	vulnQuery := fmt.Sprintf(`
		DELETE FROM vulnerabilities 
		WHERE component_id IN (
			SELECT id FROM components WHERE sbom_id IN (%s)
		)
	`, placeholders)
	_, err = tx.Exec(vulnQuery, args...)
	if err != nil {
		return fmt.Errorf("failed to delete vulnerabilities: %w", err)
	}

	// Delete components
	compQuery := fmt.Sprintf("DELETE FROM components WHERE sbom_id IN (%s)", placeholders)
	_, err = tx.Exec(compQuery, args...)
	if err != nil {
		return fmt.Errorf("failed to delete components: %w", err)
	}

	// Delete SBOMs
	sbomQuery := fmt.Sprintf("DELETE FROM sboms WHERE id IN (%s)", placeholders)
	_, err = tx.Exec(sbomQuery, args...)
	if err != nil {
		return fmt.Errorf("failed to delete SBOMs: %w", err)
	}

	return tx.Commit()
}

// DeleteRepository deletes all SBOMs and related data for a repository
func (db *Database) DeleteRepository(repoName string) error {
	// First, get all SBOM IDs for this repository
	rows, err := db.conn.Query("SELECT id FROM sboms WHERE repo_name = ?", repoName)
	if err != nil {
		return fmt.Errorf("failed to get SBOM IDs for repository: %w", err)
	}
	defer rows.Close()

	var sbomIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("failed to scan SBOM ID: %w", err)
		}
		sbomIDs = append(sbomIDs, id)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error reading SBOM IDs: %w", err)
	}

	// Use existing DeleteSBOMs method to delete all SBOMs for this repository
	return db.DeleteSBOMs(sbomIDs)
}

// GetSBOMsByRepository returns all SBOMs for a given repository
func (db *Database) GetSBOMsByRepository(repoName string) ([]*models.SBOM, error) {
	query := `
		SELECT id, repo_name, module_path, scan_date, syft_version, raw_sbom,
		       component_count, created_at, updated_at
		FROM sboms
		WHERE repo_name = ?
		ORDER BY module_path, scan_date DESC
	`

	rows, err := db.conn.Query(query, repoName)
	if err != nil {
		return nil, fmt.Errorf("failed to query SBOMs: %w", err)
	}
	defer rows.Close()

	var sboms []*models.SBOM
	for rows.Next() {
		sbom := &models.SBOM{}
		err := rows.Scan(
			&sbom.ID, &sbom.RepoName, &sbom.ModulePath, &sbom.ScanDate,
			&sbom.SyftVersion, &sbom.RawSBOM, &sbom.ComponentCount,
			&sbom.CreatedAt, &sbom.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SBOM: %w", err)
		}
		sboms = append(sboms, sbom)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading SBOMs: %w", err)
	}

	return sboms, nil
}
