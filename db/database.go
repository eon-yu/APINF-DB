package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"oss-compliance-scanner/models"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaFS embed.FS

// resolveMigrationsPath determines the correct path to migrations directory
func resolveMigrationsPath() string {
	// Check if migrations directory exists in current directory (when running from db package)
	if _, err := os.Stat("migrations"); err == nil {
		return "migrations"
	}

	// Check if db/migrations exists (when running from project root)
	if _, err := os.Stat("db/migrations"); err == nil {
		return "db/migrations"
	}

	// Fallback: try to find it relative to the current file
	if workDir, err := os.Getwd(); err == nil {
		// If we're in the db directory, use relative path
		if filepath.Base(workDir) == "db" {
			return "migrations"
		}
	}

	// Default fallback
	return "db/migrations"
}

// Database represents the database connection and operations
type Database struct {
	conn             *sql.DB
	migrationManager *MigrationManager
}

// NewDatabase creates a new database connection
func NewDatabase(driverName, dataSourceName string) (*Database, error) {
	conn, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxLifetime(5 * time.Minute)

	// Initialize migration manager with dynamic path resolution
	migrationsDir := resolveMigrationsPath()
	migrationManager := NewMigrationManager(conn, migrationsDir)

	db := &Database{
		conn:             conn,
		migrationManager: migrationManager,
	}

	// Run migrations instead of initializing schema directly
	if err := db.RunMigrations(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}

// Close closes the database connection
func (db *Database) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

// RunMigrations runs all pending database migrations
func (db *Database) RunMigrations() error {
	log.Println("Running database migrations...")
	return db.migrationManager.Migrate()
}

// GetMigrationStatus returns the current migration status
func (db *Database) GetMigrationStatus() ([]Migration, error) {
	return db.migrationManager.GetMigrationStatus()
}

// InitializeSchema creates the database schema (deprecated - use migrations)
func (db *Database) InitializeSchema() error {
	log.Println("Warning: InitializeSchema is deprecated, please use migrations instead")

	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return fmt.Errorf("failed to read schema file: %w", err)
	}

	_, err = db.conn.Exec(string(schema))
	if err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	return nil
}

// BeginTransaction starts a new database transaction
func (db *Database) BeginTransaction() (*sql.Tx, error) {
	return db.conn.Begin()
}

// SBOM Operations

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

// Component Operations

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

// Vulnerability Operations

// CreateVulnerability creates a new vulnerability record
func (db *Database) CreateVulnerability(vuln *models.Vulnerability) error {
	// Marshal JSON fields
	if err := vuln.MarshalVulnerabilityFields(); err != nil {
		return fmt.Errorf("failed to marshal vulnerability fields: %w", err)
	}

	query := `
		INSERT INTO vulnerabilities (component_id, vuln_id, severity, cvss3_score, cvss2_score,
		                           description, published_date, modified_date, urls_json,
		                           fixes_json, metadata_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query, vuln.ComponentID, vuln.VulnID, vuln.Severity,
		vuln.CVSS3Score, vuln.CVSS2Score, vuln.Description, vuln.PublishedDate,
		vuln.ModifiedDate, vuln.URLsJSON, vuln.FixesJSON, vuln.MetadataJSON)
	if err != nil {
		return fmt.Errorf("failed to create vulnerability: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get vulnerability ID: %w", err)
	}

	vuln.ID = int(id)
	return nil
}

// GetVulnerabilitiesByComponent retrieves vulnerabilities for a specific component
func (db *Database) GetVulnerabilitiesByComponent(componentID int) ([]*models.Vulnerability, error) {
	query := `
		SELECT id, component_id, vuln_id, severity, cvss2_score, cvss3_score, description,
		       urls_json, published_date, modified_date, fixes_json, metadata_json, created_at, updated_at
		FROM vulnerabilities
		WHERE component_id = ?
		ORDER BY severity DESC, created_at DESC
	`

	rows, err := db.conn.Query(query, componentID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []*models.Vulnerability
	for rows.Next() {
		vuln := &models.Vulnerability{}
		err := rows.Scan(
			&vuln.ID, &vuln.ComponentID, &vuln.VulnID, &vuln.Severity,
			&vuln.CVSS2Score, &vuln.CVSS3Score, &vuln.Description,
			&vuln.URLsJSON, &vuln.PublishedDate, &vuln.ModifiedDate,
			&vuln.FixesJSON, &vuln.MetadataJSON, &vuln.CreatedAt, &vuln.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
		}

		// Unmarshal JSON fields
		if err := vuln.UnmarshalVulnerabilityFields(); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vulnerability fields: %w", err)
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating vulnerabilities: %w", err)
	}

	return vulnerabilities, nil
}

// GetVulnerabilitiesBySBOM retrieves vulnerabilities for a specific SBOM with component information
func (db *Database) GetVulnerabilitiesBySBOM(sbomID int) ([]*models.Vulnerability, error) {
	query := `
		SELECT v.id, v.component_id, v.vuln_id, v.severity, v.cvss2_score, v.cvss3_score,
		       v.description, v.urls_json, v.published_date, v.modified_date, v.fixes_json,
		       v.metadata_json, v.created_at, v.updated_at,
		       c.name as component_name, c.version as component_version, c.type as component_type
		FROM vulnerabilities v
		JOIN components c ON v.component_id = c.id
		WHERE c.sbom_id = ?
		ORDER BY v.severity DESC, c.name ASC, v.created_at DESC
	`

	rows, err := db.conn.Query(query, sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities by SBOM: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []*models.Vulnerability
	for rows.Next() {
		vuln := &models.Vulnerability{}
		var componentName, componentVersion, componentType string

		err := rows.Scan(
			&vuln.ID, &vuln.ComponentID, &vuln.VulnID, &vuln.Severity,
			&vuln.CVSS2Score, &vuln.CVSS3Score, &vuln.Description,
			&vuln.URLsJSON, &vuln.PublishedDate, &vuln.ModifiedDate,
			&vuln.FixesJSON, &vuln.MetadataJSON, &vuln.CreatedAt, &vuln.UpdatedAt,
			&componentName, &componentVersion, &componentType,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
		}

		// Unmarshal JSON fields
		if err := vuln.UnmarshalVulnerabilityFields(); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vulnerability fields: %w", err)
		}

		// Add actual component info to metadata
		if vuln.Metadata == nil {
			vuln.Metadata = make(map[string]interface{})
		}
		vuln.Metadata["component_name"] = componentName
		vuln.Metadata["component_version"] = componentVersion
		vuln.Metadata["component_type"] = componentType
		vuln.Metadata["component_id"] = vuln.ComponentID

		vulnerabilities = append(vulnerabilities, vuln)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating vulnerabilities: %w", err)
	}

	return vulnerabilities, nil
}

// GetAllVulnerabilities retrieves all vulnerabilities with component information
func (db *Database) GetAllVulnerabilities(limit int) ([]*models.Vulnerability, error) {
	query := `
		SELECT v.id, v.component_id, v.vuln_id, v.severity, v.cvss2_score, v.cvss3_score,
		       v.description, v.urls_json, v.published_date, v.modified_date, v.fixes_json,
		       v.metadata_json, v.created_at, v.updated_at,
		       c.name as component_name, c.version as component_version, c.type as component_type,
		       s.repo_name, s.module_path
		FROM vulnerabilities v
		JOIN components c ON v.component_id = c.id
		JOIN sboms s ON c.sbom_id = s.id
		ORDER BY
			CASE v.severity
				WHEN 'Critical' THEN 1
				WHEN 'High' THEN 2
				WHEN 'Medium' THEN 3
				WHEN 'Low' THEN 4
				ELSE 5
			END,
			v.created_at DESC
		LIMIT ?
	`

	rows, err := db.conn.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query all vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []*models.Vulnerability
	for rows.Next() {
		vuln := &models.Vulnerability{}
		var componentName, componentVersion, componentType, repoName, modulePath string

		err := rows.Scan(
			&vuln.ID, &vuln.ComponentID, &vuln.VulnID, &vuln.Severity,
			&vuln.CVSS2Score, &vuln.CVSS3Score, &vuln.Description,
			&vuln.URLsJSON, &vuln.PublishedDate, &vuln.ModifiedDate,
			&vuln.FixesJSON, &vuln.MetadataJSON, &vuln.CreatedAt, &vuln.UpdatedAt,
			&componentName, &componentVersion, &componentType, &repoName, &modulePath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability: %w", err)
		}

		// Unmarshal JSON fields
		if err := vuln.UnmarshalVulnerabilityFields(); err != nil {
			return nil, fmt.Errorf("failed to unmarshal vulnerability fields: %w", err)
		}

		// Add component and repository info to metadata
		if vuln.Metadata == nil {
			vuln.Metadata = make(map[string]interface{})
		}
		vuln.Metadata["component_name"] = componentName
		vuln.Metadata["component_version"] = componentVersion
		vuln.Metadata["component_type"] = componentType
		vuln.Metadata["repo_name"] = repoName
		vuln.Metadata["module_path"] = modulePath

		vulnerabilities = append(vulnerabilities, vuln)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating vulnerabilities: %w", err)
	}

	return vulnerabilities, nil
}

// Policy Operations

// CreateLicensePolicy creates a new license policy
func (db *Database) CreateLicensePolicy(policy *models.LicensePolicy) error {
	query := `
		INSERT INTO license_policies (license_name, action, reason, is_active)
		VALUES (?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query, policy.LicenseName, policy.Action, policy.Reason, policy.IsActive)
	if err != nil {
		return fmt.Errorf("failed to create license policy: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get license policy ID: %w", err)
	}

	policy.ID = int(id)
	return nil
}

// GetActiveLicensePolicies retrieves all active license policies
func (db *Database) GetActiveLicensePolicies() ([]*models.LicensePolicy, error) {
	query := `
		SELECT id, license_name, action, reason, is_active, created_at, updated_at
		FROM license_policies WHERE is_active = TRUE
		ORDER BY license_name
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query license policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.LicensePolicy
	for rows.Next() {
		policy := &models.LicensePolicy{}
		err := rows.Scan(
			&policy.ID, &policy.LicenseName, &policy.Action, &policy.Reason,
			&policy.IsActive, &policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan license policy: %w", err)
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating license policies: %w", err)
	}

	return policies, nil
}

// CreateVulnerabilityPolicy creates a new vulnerability policy
func (db *Database) CreateVulnerabilityPolicy(policy *models.VulnerabilityPolicy) error {
	query := `
		INSERT INTO vulnerability_policies (min_severity_level, max_cvss_score, action,
		                                  ignore_fix_available, grace_period_days, is_active)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	result, err := db.conn.Exec(query, policy.MinSeverityLevel, policy.MaxCVSSScore, policy.Action,
		policy.IgnoreFixAvailable, policy.GracePeriodDays, policy.IsActive)
	if err != nil {
		return fmt.Errorf("failed to create vulnerability policy: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get vulnerability policy ID: %w", err)
	}

	policy.ID = int(id)
	return nil
}

// GetActiveVulnerabilityPolicies retrieves all active vulnerability policies
func (db *Database) GetActiveVulnerabilityPolicies() ([]*models.VulnerabilityPolicy, error) {
	query := `
		SELECT id, min_severity_level, max_cvss_score, action, ignore_fix_available,
		       grace_period_days, is_active, created_at, updated_at
		FROM vulnerability_policies WHERE is_active = TRUE
		ORDER BY max_cvss_score DESC
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability policies: %w", err)
	}
	defer rows.Close()

	var policies []*models.VulnerabilityPolicy
	for rows.Next() {
		policy := &models.VulnerabilityPolicy{}
		err := rows.Scan(
			&policy.ID, &policy.MinSeverityLevel, &policy.MaxCVSSScore, &policy.Action,
			&policy.IgnoreFixAvailable, &policy.GracePeriodDays, &policy.IsActive,
			&policy.CreatedAt, &policy.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability policy: %w", err)
		}
		policies = append(policies, policy)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating vulnerability policies: %w", err)
	}

	return policies, nil
}

// ScanResult Operations

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

// Ping checks database connectivity
func (db *Database) Ping() error {
	return db.conn.Ping()
}

// DeleteLicensePolicy deletes a license policy by ID
func (db *Database) DeleteLicensePolicy(id int) error {
	query := `DELETE FROM license_policies WHERE id = ?`

	result, err := db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete license policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("license policy not found with ID %d", id)
	}

	return nil
}

// DeleteVulnerabilityPolicy deletes a vulnerability policy by ID
func (db *Database) DeleteVulnerabilityPolicy(id int) error {
	query := `DELETE FROM vulnerability_policies WHERE id = ?`

	result, err := db.conn.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete vulnerability policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("vulnerability policy not found with ID %d", id)
	}

	return nil
}

// Generic database methods for tenant manager compatibility

// Query executes a query that returns rows
func (db *Database) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return db.conn.Query(query, args...)
}

// QueryRow executes a query that is expected to return at most one row
func (db *Database) QueryRow(query string, args ...interface{}) *sql.Row {
	return db.conn.QueryRow(query, args...)
}

// Exec executes a query without returning any rows
func (db *Database) Exec(query string, args ...interface{}) (sql.Result, error) {
	return db.conn.Exec(query, args...)
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

// getTopVulnerabilities gets top vulnerabilities for a repository
func (db *Database) getTopVulnerabilities(repoName string, whereClause string, args []interface{}, limit int) ([]models.VulnerabilityReport, error) {
	// Build query to get top vulnerabilities
	vulnQuery := fmt.Sprintf(`
		SELECT DISTINCT
			v.vuln_id,
			v.severity,
			v.cvss3_score,
			v.description,
			c.name as component_name,
			c.version as component_version,
			s.repo_name,
			v.published_date,
			CASE WHEN v.fixes_json IS NOT NULL AND v.fixes_json != '[]' THEN 1 ELSE 0 END as fix_available
		FROM vulnerabilities v
		JOIN components c ON v.component_id = c.id
		JOIN sboms s ON c.sbom_id = s.id
		WHERE %s AND s.repo_name = ?
		ORDER BY 
			CASE v.severity 
				WHEN 'Critical' THEN 4 
				WHEN 'High' THEN 3 
				WHEN 'Medium' THEN 2 
				WHEN 'Low' THEN 1 
				ELSE 0 
			END DESC,
			v.cvss3_score DESC
		LIMIT ?`, whereClause)

	vulnArgs := append(args, repoName, limit)
	rows, err := db.conn.Query(vulnQuery, vulnArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to get top vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []models.VulnerabilityReport
	for rows.Next() {
		var vuln models.VulnerabilityReport
		var fixAvailable int

		err := rows.Scan(
			&vuln.VulnID, &vuln.Severity, &vuln.CVSS3Score,
			&vuln.Description, &vuln.ComponentName, &vuln.ComponentVersion,
			&vuln.RepoName, &vuln.PublishedDate, &fixAvailable,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability report: %w", err)
		}

		vuln.FixAvailable = fixAvailable == 1
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}
