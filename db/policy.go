package db

import (
	"fmt"
	"oss-compliance-scanner/models"
)

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
