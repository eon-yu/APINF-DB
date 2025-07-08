package db

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oss-compliance-scanner/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestDB creates a temporary test database
func setupTestDB(t *testing.T) (*Database, func()) {
	// Create temporary directory for test database
	tempDir, err := os.MkdirTemp("", "db_test_*")
	require.NoError(t, err)

	dbPath := filepath.Join(tempDir, "test.db")
	db, err := NewDatabase("sqlite3", dbPath)
	require.NoError(t, err)

	cleanup := func() {
		db.Close()
		os.RemoveAll(tempDir)
	}

	return db, cleanup
}

func TestNewDatabase(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "db_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "test.db")

	db, err := NewDatabase("sqlite3", dbPath)
	assert.NoError(t, err)
	assert.NotNil(t, db)
	assert.NotNil(t, db.conn)
	assert.NotNil(t, db.migrationManager)

	// Test that database is accessible
	err = db.Ping()
	assert.NoError(t, err)

	db.Close()
}

func TestNewDatabase_InvalidDriver(t *testing.T) {
	_, err := NewDatabase("invalid_driver", "test.db")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

func TestDatabase_Close(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	err := db.Close()
	assert.NoError(t, err)

	// Closing again should not error
	err = db.Close()
	assert.NoError(t, err)
}

func TestDatabase_Ping(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	err := db.Ping()
	assert.NoError(t, err)
}

func TestDatabase_BeginTransaction(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	tx, err := db.BeginTransaction()
	assert.NoError(t, err)
	assert.NotNil(t, tx)

	err = tx.Rollback()
	assert.NoError(t, err)
}

// SBOM Tests

func TestDatabase_CreateSBOM(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 5,
	}

	err := db.CreateSBOM(sbom)
	assert.NoError(t, err)
	assert.NotZero(t, sbom.ID)
}

func TestDatabase_GetSBOM(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create test SBOM
	originalSBOM := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     "module1",
		ScanDate:       time.Now().Truncate(time.Second), // Truncate for comparison
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 5,
	}

	err := db.CreateSBOM(originalSBOM)
	require.NoError(t, err)

	// Retrieve SBOM
	retrievedSBOM, err := db.GetSBOM(originalSBOM.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedSBOM)
	assert.Equal(t, originalSBOM.RepoName, retrievedSBOM.RepoName)
	assert.Equal(t, originalSBOM.ModulePath, retrievedSBOM.ModulePath)
	assert.Equal(t, originalSBOM.SyftVersion, retrievedSBOM.SyftVersion)
	assert.Equal(t, originalSBOM.ComponentCount, retrievedSBOM.ComponentCount)
}

func TestDatabase_GetSBOM_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.GetSBOM(999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SBOM not found")
}

func TestDatabase_GetLatestSBOM(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create multiple SBOMs with different scan dates
	sbom1 := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now().Add(-2 * time.Hour),
		SyftVersion:    "0.81.0",
		RawSBOM:        `{"old": "data"}`,
		ComponentCount: 3,
	}
	err := db.CreateSBOM(sbom1)
	require.NoError(t, err)

	sbom2 := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"new": "data"}`,
		ComponentCount: 5,
	}
	err = db.CreateSBOM(sbom2)
	require.NoError(t, err)

	// Get latest SBOM
	latest, err := db.GetLatestSBOM("test-repo", ".")
	assert.NoError(t, err)
	assert.NotNil(t, latest)
	assert.Equal(t, sbom2.ID, latest.ID)
	assert.Equal(t, "0.82.0", latest.SyftVersion)
}

func TestDatabase_GetLatestSBOM_NotFound(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := db.GetLatestSBOM("non-existent", ".")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no SBOM found")
}

func TestDatabase_GetAllSBOMs(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create multiple SBOMs
	for i := 0; i < 3; i++ {
		sbom := &models.SBOM{
			RepoName:       "test-repo",
			ModulePath:     ".",
			ScanDate:       time.Now().Add(-time.Duration(i) * time.Hour),
			SyftVersion:    "0.82.0",
			RawSBOM:        `{"test": "data"}`,
			ComponentCount: 5,
		}
		err := db.CreateSBOM(sbom)
		require.NoError(t, err)
	}

	// Get all SBOMs with limit
	sboms, err := db.GetAllSBOMs(10)
	assert.NoError(t, err)
	assert.Len(t, sboms, 3)

	// Test with smaller limit
	sboms, err = db.GetAllSBOMs(2)
	assert.NoError(t, err)
	assert.Len(t, sboms, 2)
}

// Component Tests

func TestDatabase_CreateComponent(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM first
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 1,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	component := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "test-component",
		Version:  "1.0.0",
		Type:     "library",
		Language: "go",
		PURL:     "pkg:golang/test-component@1.0.0",
	}

	err = db.CreateComponent(component)
	assert.NoError(t, err)
	assert.NotZero(t, component.ID)
}

func TestDatabase_GetComponentsBySBOM(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 2,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	// Create components
	component1 := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "component1",
		Version:  "1.0.0",
		Type:     "library",
		Language: "go",
	}
	err = db.CreateComponent(component1)
	require.NoError(t, err)

	component2 := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "component2",
		Version:  "2.0.0",
		Type:     "library",
		Language: "go",
	}
	err = db.CreateComponent(component2)
	require.NoError(t, err)

	// Get components
	components, err := db.GetComponentsBySBOM(sbom.ID)
	assert.NoError(t, err)
	assert.Len(t, components, 2)
}

func TestDatabase_GetComponent(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM and component
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 1,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	originalComponent := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "test-component",
		Version:  "1.0.0",
		Type:     "library",
		Language: "go",
		PURL:     "pkg:golang/test-component@1.0.0",
	}
	err = db.CreateComponent(originalComponent)
	require.NoError(t, err)

	// Retrieve component
	retrievedComponent, err := db.GetComponent(originalComponent.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedComponent)
	assert.Equal(t, originalComponent.Name, retrievedComponent.Name)
	assert.Equal(t, originalComponent.Version, retrievedComponent.Version)
	assert.Equal(t, originalComponent.PURL, retrievedComponent.PURL)
}

// Vulnerability Tests

func TestDatabase_CreateVulnerability(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM and component first
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 1,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	component := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "vulnerable-component",
		Version:  "1.0.0",
		Type:     "library",
		Language: "go",
	}
	err = db.CreateComponent(component)
	require.NoError(t, err)

	vulnerability := &models.Vulnerability{
		ComponentID: component.ID,
		VulnID:      "CVE-2023-1234",
		Severity:    "High",
		CVSS3Score:  7.5,
		Description: "Test vulnerability",
	}

	err = db.CreateVulnerability(vulnerability)
	assert.NoError(t, err)
	assert.NotZero(t, vulnerability.ID)
}

func TestDatabase_GetVulnerabilitiesByComponent(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM and component
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 1,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	component := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "vulnerable-component",
		Version:  "1.0.0",
		Type:     "library",
		Language: "go",
	}
	err = db.CreateComponent(component)
	require.NoError(t, err)

	// Create vulnerabilities
	vuln1 := &models.Vulnerability{
		ComponentID: component.ID,
		VulnID:      "CVE-2023-1234",
		Severity:    "High",
		CVSS3Score:  7.5,
		Description: "Test vulnerability 1",
	}
	err = db.CreateVulnerability(vuln1)
	require.NoError(t, err)

	vuln2 := &models.Vulnerability{
		ComponentID: component.ID,
		VulnID:      "CVE-2023-5678",
		Severity:    "Medium",
		CVSS3Score:  5.0,
		Description: "Test vulnerability 2",
	}
	err = db.CreateVulnerability(vuln2)
	require.NoError(t, err)

	// Get vulnerabilities
	vulns, err := db.GetVulnerabilitiesByComponent(component.ID)
	assert.NoError(t, err)
	assert.Len(t, vulns, 2)
}

func TestDatabase_GetAllVulnerabilities(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create test data
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 1,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	component := &models.Component{
		SBOMID:   sbom.ID,
		Name:     "vulnerable-component",
		Version:  "1.0.0",
		Type:     "library",
		Language: "go",
	}
	err = db.CreateComponent(component)
	require.NoError(t, err)

	// Create multiple vulnerabilities
	for i := 0; i < 3; i++ {
		vuln := &models.Vulnerability{
			ComponentID: component.ID,
			VulnID:      fmt.Sprintf("CVE-2023-%04d", 1000+i),
			Severity:    "Medium",
			CVSS3Score:  5.0,
			Description: fmt.Sprintf("Test vulnerability %d", i+1),
		}
		err = db.CreateVulnerability(vuln)
		require.NoError(t, err)
	}

	// Get all vulnerabilities
	vulns, err := db.GetAllVulnerabilities(10)
	assert.NoError(t, err)
	assert.Len(t, vulns, 3)
}

// Policy Tests

func TestDatabase_CreateLicensePolicy(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	policy := &models.LicensePolicy{
		LicenseName: "GPL-3.0",
		Action:      "block",
		IsActive:    true,
	}

	err := db.CreateLicensePolicy(policy)
	assert.NoError(t, err)
	assert.NotZero(t, policy.ID)
}

func TestDatabase_GetActiveLicensePolicies(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create active policy
	activePolicy := &models.LicensePolicy{
		LicenseName: "GPL-3.0",
		Action:      "block",
		IsActive:    true,
	}
	err := db.CreateLicensePolicy(activePolicy)
	require.NoError(t, err)

	// Create inactive policy
	inactivePolicy := &models.LicensePolicy{
		LicenseName: "MIT",
		Action:      "allow",
		IsActive:    false,
	}
	err = db.CreateLicensePolicy(inactivePolicy)
	require.NoError(t, err)

	// Get active policies
	policies, err := db.GetActiveLicensePolicies()
	assert.NoError(t, err)
	assert.Len(t, policies, 1)
	assert.Equal(t, "GPL-3.0", policies[0].LicenseName)
}

func TestDatabase_CreateVulnerabilityPolicy(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	policy := &models.VulnerabilityPolicy{
		MinSeverityLevel: "High",
		Action:           "fail",
		IsActive:         true,
	}

	err := db.CreateVulnerabilityPolicy(policy)
	assert.NoError(t, err)
	assert.NotZero(t, policy.ID)
}

func TestDatabase_DeleteLicensePolicy(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create policy
	policy := &models.LicensePolicy{
		LicenseName: "GPL-3.0",
		Action:      "block",
		IsActive:    true,
	}
	err := db.CreateLicensePolicy(policy)
	require.NoError(t, err)

	// Delete policy
	err = db.DeleteLicensePolicy(policy.ID)
	assert.NoError(t, err)

	// Verify deletion - should not be in active policies
	policies, err := db.GetActiveLicensePolicies()
	assert.NoError(t, err)
	assert.Empty(t, policies)
}

func TestDatabase_DeleteVulnerabilityPolicy(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create policy
	policy := &models.VulnerabilityPolicy{
		MinSeverityLevel: "High",
		Action:           "fail",
		IsActive:         true,
	}
	err := db.CreateVulnerabilityPolicy(policy)
	require.NoError(t, err)

	// Delete policy
	err = db.DeleteVulnerabilityPolicy(policy.ID)
	assert.NoError(t, err)

	// Verify deletion
	policies, err := db.GetActiveVulnerabilityPolicies()
	assert.NoError(t, err)
	assert.Empty(t, policies)
}

// ScanResult Tests

func TestDatabase_CreateScanResult(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM first
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 1,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	scanResult := &models.ScanResult{
		SBOMID:               sbom.ID,
		RepoName:             "test-repo",
		ModulePath:           ".",
		ScanStartTime:        time.Now().Add(-time.Minute),
		ScanEndTime:          time.Now(),
		Status:               models.ScanStatusCompleted,
		TotalComponents:      1,
		VulnerabilitiesFound: 20,
		LicenseViolations:    0,
		CriticalVulns:        0,
		HighVulns:            5,
		MediumVulns:          10,
		LowVulns:             15,
		OverallRisk:          models.RiskLevelHigh,
	}

	err = db.CreateScanResult(scanResult)
	assert.NoError(t, err)
	assert.NotZero(t, scanResult.ID)
}

func TestDatabase_GetLatestScanResults(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 1,
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	// Create scan results
	for i := 0; i < 3; i++ {
		scanResult := &models.ScanResult{
			SBOMID:               sbom.ID,
			RepoName:             "test-repo",
			ModulePath:           ".",
			ScanStartTime:        time.Now().Add(-time.Duration(i) * time.Hour),
			ScanEndTime:          time.Now().Add(-time.Duration(i)*time.Hour + time.Minute),
			Status:               models.ScanStatusCompleted,
			TotalComponents:      1,
			VulnerabilitiesFound: i * 10,
			LicenseViolations:    0,
			CriticalVulns:        0,
			HighVulns:            i * 2,
			MediumVulns:          i * 3,
			LowVulns:             i * 5,
			OverallRisk:          models.RiskLevelMedium,
		}
		err = db.CreateScanResult(scanResult)
		require.NoError(t, err)
	}

	// Get latest scan results
	results, err := db.GetLatestScanResults(10)
	assert.NoError(t, err)
	assert.Len(t, results, 3)
}

// Generic database method tests

func TestDatabase_Query(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	assert.NoError(t, err)
	assert.NotNil(t, rows)
	rows.Close()
}

func TestDatabase_QueryRow(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	row := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
	assert.NotNil(t, row)

	var count int
	err := row.Scan(&count)
	assert.NoError(t, err)
	assert.Greater(t, count, 0)
}

func TestDatabase_Exec(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	result, err := db.Exec("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Clean up
	_, err = db.Exec("DROP TABLE test_table")
	assert.NoError(t, err)
}

func TestDatabase_UpdateSBOMComponentCount(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Create SBOM
	sbom := &models.SBOM{
		RepoName:       "test-repo",
		ModulePath:     ".",
		ScanDate:       time.Now(),
		SyftVersion:    "0.82.0",
		RawSBOM:        `{"test": "data"}`,
		ComponentCount: 0, // Start with 0
	}
	err := db.CreateSBOM(sbom)
	require.NoError(t, err)

	// Add components
	for i := 0; i < 3; i++ {
		component := &models.Component{
			SBOMID:   sbom.ID,
			Name:     fmt.Sprintf("component%d", i),
			Version:  "1.0.0",
			Type:     "library",
			Language: "go",
		}
		err = db.CreateComponent(component)
		require.NoError(t, err)
	}

	// Update component count
	err = db.UpdateSBOMComponentCount(sbom.ID)
	assert.NoError(t, err)

	// Verify count was updated
	updatedSBOM, err := db.GetSBOM(sbom.ID)
	assert.NoError(t, err)
	assert.Equal(t, 3, updatedSBOM.ComponentCount)
}
