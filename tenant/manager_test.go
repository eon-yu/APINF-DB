package tenant

import (
	"os"
	"path/filepath"
	"testing"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestTenantManager creates a test database and tenant manager
func setupTestTenantManager(t *testing.T) (*TenantManager, func()) {
	// Create temporary directory for test database
	tempDir, err := os.MkdirTemp("", "tenant_test_*")
	require.NoError(t, err)

	dbPath := filepath.Join(tempDir, "test.db")
	database, err := db.NewDatabase("sqlite3", dbPath)
	require.NoError(t, err)

	// Create tenants table
	createTenantsTable := `
		CREATE TABLE IF NOT EXISTS tenants (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			domain TEXT UNIQUE,
			settings TEXT,
			created_at DATETIME,
			updated_at DATETIME,
			is_active BOOLEAN DEFAULT 1,
			metadata TEXT
		);
	`
	_, err = database.Exec(createTenantsTable)
	require.NoError(t, err)

	// Create tenant_users table
	createTenantUsersTable := `
		CREATE TABLE IF NOT EXISTS tenant_users (
			user_id TEXT,
			tenant_id TEXT,
			role TEXT,
			email TEXT,
			name TEXT,
			created_at DATETIME,
			is_active BOOLEAN DEFAULT 1,
			PRIMARY KEY (user_id, tenant_id)
		);
	`
	_, err = database.Exec(createTenantUsersTable)
	require.NoError(t, err)

	// Create tenant_resources table
	createTenantResourcesTable := `
		CREATE TABLE IF NOT EXISTS tenant_resources (
			resource_id TEXT PRIMARY KEY,
			tenant_id TEXT,
			resource_type TEXT,
			resource_name TEXT,
			path TEXT,
			created_at DATETIME,
			updated_at DATETIME,
			is_active BOOLEAN DEFAULT 1
		);
	`
	_, err = database.Exec(createTenantResourcesTable)
	require.NoError(t, err)

	tm := NewTenantManager(database)

	cleanup := func() {
		database.Close()
		os.RemoveAll(tempDir)
	}

	return tm, cleanup
}

func TestNewTenantManager(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	assert.NotNil(t, tm)
	assert.NotNil(t, tm.database)
}

func TestTenantManager_CreateTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	tenant := &Tenant{
		Name:        "Test Organization",
		Description: "Test tenant for unit testing",
		Domain:      "testorg.com",
		Settings: TenantSettings{
			DefaultPolicies: TenantPolicies{
				LicensePolicies: []models.LicensePolicy{
					{
						LicenseName: "MIT",
						Action:      models.PolicyActionAllow,
						IsActive:    true,
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"test_key": "test_value",
		},
	}

	err := tm.CreateTenant(tenant)
	assert.NoError(t, err)
	assert.NotEmpty(t, tenant.ID)
	assert.True(t, tenant.IsActive)
	assert.False(t, tenant.CreatedAt.IsZero())
	assert.False(t, tenant.UpdatedAt.IsZero())
}

func TestTenantManager_CreateTenant_WithCustomID(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	tenant := &Tenant{
		ID:          "custom-tenant-id",
		Name:        "Custom Tenant",
		Description: "Tenant with custom ID",
		Domain:      "custom.com",
	}

	err := tm.CreateTenant(tenant)
	assert.NoError(t, err)
	assert.Equal(t, "custom-tenant-id", tenant.ID)
}

func TestTenantManager_CreateTenant_ValidationFails(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Test with empty name
	tenant := &Tenant{
		Name:   "", // Empty name should fail validation
		Domain: "test.com",
	}

	err := tm.CreateTenant(tenant)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tenant")
}

func TestTenantManager_GetTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant first
	originalTenant := &Tenant{
		Name:        "Get Test Tenant",
		Description: "Tenant for get operation test",
		Domain:      "gettest.com",
		Settings: TenantSettings{
			CustomRules: []string{"rule1", "rule2"},
		},
	}

	err := tm.CreateTenant(originalTenant)
	require.NoError(t, err)

	// Retrieve the tenant
	retrievedTenant, err := tm.GetTenant(originalTenant.ID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedTenant)
	assert.Equal(t, originalTenant.ID, retrievedTenant.ID)
	assert.Equal(t, originalTenant.Name, retrievedTenant.Name)
	assert.Equal(t, originalTenant.Description, retrievedTenant.Description)
	assert.Equal(t, originalTenant.Domain, retrievedTenant.Domain)
	assert.Equal(t, len(originalTenant.Settings.CustomRules), len(retrievedTenant.Settings.CustomRules))
}

func TestTenantManager_GetTenant_NotFound(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	_, err := tm.GetTenant("non-existent-tenant")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant not found")
}

func TestTenantManager_GetTenantByDomain(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant
	tenant := &Tenant{
		Name:   "Domain Test Tenant",
		Domain: "domaintest.com",
	}

	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Retrieve by domain
	retrievedTenant, err := tm.GetTenantByDomain("domaintest.com")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedTenant)
	assert.Equal(t, tenant.ID, retrievedTenant.ID)
	assert.Equal(t, "domaintest.com", retrievedTenant.Domain)
}

func TestTenantManager_GetTenantByDomain_NotFound(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	_, err := tm.GetTenantByDomain("nonexistent.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant not found")
}

func TestTenantManager_ListTenants(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create multiple tenants
	tenant1 := &Tenant{
		Name:   "Alpha Tenant",
		Domain: "alpha.com",
	}
	err := tm.CreateTenant(tenant1)
	require.NoError(t, err)

	tenant2 := &Tenant{
		Name:   "Beta Tenant",
		Domain: "beta.com",
	}
	err = tm.CreateTenant(tenant2)
	require.NoError(t, err)

	// List tenants
	tenants, err := tm.ListTenants()
	assert.NoError(t, err)
	assert.Len(t, tenants, 2)

	// Should be sorted by name
	assert.Equal(t, "Alpha Tenant", tenants[0].Name)
	assert.Equal(t, "Beta Tenant", tenants[1].Name)
}

func TestTenantManager_UpdateTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant
	tenant := &Tenant{
		Name:        "Original Name",
		Description: "Original description",
		Domain:      "original.com",
	}

	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Update the tenant
	tenant.Name = "Updated Name"
	tenant.Description = "Updated description"

	err = tm.UpdateTenant(tenant)
	assert.NoError(t, err)

	// Verify the update
	updatedTenant, err := tm.GetTenant(tenant.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", updatedTenant.Name)
	assert.Equal(t, "Updated description", updatedTenant.Description)
}

func TestTenantManager_DeleteTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant
	tenant := &Tenant{
		Name:   "To Be Deleted",
		Domain: "delete.com",
	}

	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Delete the tenant
	err = tm.DeleteTenant(tenant.ID)
	assert.NoError(t, err)

	// Verify deletion - should not be found
	_, err = tm.GetTenant(tenant.ID)
	assert.Error(t, err)
}

// User Management Tests

func TestTenantManager_AddUserToTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant first
	tenant := &Tenant{
		Name:   "User Test Tenant",
		Domain: "usertest.com",
	}
	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Add user to tenant
	err = tm.AddUserToTenant(tenant.ID, "user123", "user@usertest.com", "Test User", "admin")
	assert.NoError(t, err)
}

func TestTenantManager_AddUserToTenant_InvalidRole(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant first
	tenant := &Tenant{
		Name:   "Role Test Tenant",
		Domain: "roletest.com",
	}
	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Try to add user with invalid role
	err = tm.AddUserToTenant(tenant.ID, "user123", "user@roletest.com", "Test User", "invalid_role")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid role")
}

func TestTenantManager_GetTenantUsers(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant
	tenant := &Tenant{
		Name:   "Users Test Tenant",
		Domain: "userstest.com",
	}
	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Add multiple users
	err = tm.AddUserToTenant(tenant.ID, "user1", "user1@userstest.com", "User One", "admin")
	require.NoError(t, err)

	err = tm.AddUserToTenant(tenant.ID, "user2", "user2@userstest.com", "User Two", "viewer")
	require.NoError(t, err)

	// Get tenant users
	users, err := tm.GetTenantUsers(tenant.ID)
	assert.NoError(t, err)
	assert.Len(t, users, 2)

	// Check user details
	userMap := make(map[string]*TenantUser)
	for _, user := range users {
		userMap[user.UserID] = user
	}

	assert.Equal(t, "admin", userMap["user1"].Role)
	assert.Equal(t, "viewer", userMap["user2"].Role)
	assert.Equal(t, "User One", userMap["user1"].Name)
	assert.Equal(t, "User Two", userMap["user2"].Name)
}

func TestTenantManager_GetUserTenants(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create multiple tenants
	tenant1 := &Tenant{
		Name:   "Tenant One",
		Domain: "tenant1.com",
	}
	err := tm.CreateTenant(tenant1)
	require.NoError(t, err)

	tenant2 := &Tenant{
		Name:   "Tenant Two",
		Domain: "tenant2.com",
	}
	err = tm.CreateTenant(tenant2)
	require.NoError(t, err)

	// Add user to both tenants
	err = tm.AddUserToTenant(tenant1.ID, "user123", "user@example.com", "Test User", "admin")
	require.NoError(t, err)

	err = tm.AddUserToTenant(tenant2.ID, "user123", "user@example.com", "Test User", "viewer")
	require.NoError(t, err)

	// Get user's tenants
	tenants, err := tm.GetUserTenants("user123")
	assert.NoError(t, err)
	assert.Len(t, tenants, 2)
}

// Resource Management Tests

func TestTenantManager_AssignResourceToTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant
	tenant := &Tenant{
		Name:   "Resource Test Tenant",
		Domain: "resourcetest.com",
	}
	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Assign resource to tenant
	err = tm.AssignResourceToTenant(tenant.ID, "repository", "test-repo", "/path/to/repo")
	assert.NoError(t, err)
}

func TestTenantManager_GetTenantResources(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant
	tenant := &Tenant{
		Name:   "Resources Test Tenant",
		Domain: "resourcestest.com",
	}
	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Assign multiple resources
	err = tm.AssignResourceToTenant(tenant.ID, "repository", "repo1", "/path/to/repo1")
	require.NoError(t, err)

	err = tm.AssignResourceToTenant(tenant.ID, "module", "module1", "/path/to/module1")
	require.NoError(t, err)

	// Get tenant resources
	resources, err := tm.GetTenantResources(tenant.ID)
	assert.NoError(t, err)
	assert.Len(t, resources, 2)

	// Check resource details
	resourceMap := make(map[string]*TenantResource)
	for _, resource := range resources {
		resourceMap[resource.ResourceName] = resource
	}

	assert.Equal(t, "repository", resourceMap["repo1"].ResourceType)
	assert.Equal(t, "module", resourceMap["module1"].ResourceType)
	assert.Equal(t, "/path/to/repo1", resourceMap["repo1"].Path)
	assert.Equal(t, "/path/to/module1", resourceMap["module1"].Path)
}

func TestTenantManager_GetResourceTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Create a tenant
	tenant := &Tenant{
		Name:   "Resource Owner Tenant",
		Domain: "resourceowner.com",
	}
	err := tm.CreateTenant(tenant)
	require.NoError(t, err)

	// Assign resource to tenant
	err = tm.AssignResourceToTenant(tenant.ID, "repository", "owned-repo", "/path/to/owned-repo")
	require.NoError(t, err)

	// Get resource's tenant
	ownerTenant, err := tm.GetResourceTenant("repository", "owned-repo")
	assert.NoError(t, err)
	assert.NotNil(t, ownerTenant)
	assert.Equal(t, tenant.ID, ownerTenant.ID)
	assert.Equal(t, tenant.Name, ownerTenant.Name)
}

func TestTenantManager_GetResourceTenant_NotFound(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	_, err := tm.GetResourceTenant("repository", "non-existent-repo")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// Utility function tests

func TestGenerateTenantID(t *testing.T) {
	id1 := generateTenantID("Test Organization")
	assert.NotEmpty(t, id1)
	assert.True(t, isValidTenantID(id1))

	// Should be consistent
	id2 := generateTenantID("Test Organization")
	assert.Equal(t, id1, id2)

	// Different names should generate different IDs
	id3 := generateTenantID("Different Organization")
	assert.NotEqual(t, id1, id3)
}

func TestGenerateResourceID(t *testing.T) {
	id1 := generateResourceID("repository", "test-repo")
	assert.NotEmpty(t, id1)

	// Should be consistent
	id2 := generateResourceID("repository", "test-repo")
	assert.Equal(t, id1, id2)

	// Different resource should generate different ID
	id3 := generateResourceID("module", "test-repo")
	assert.NotEqual(t, id1, id3)
}

func TestIsValidRole(t *testing.T) {
	assert.True(t, isValidRole("admin"))
	assert.True(t, isValidRole("viewer"))
	assert.True(t, isValidRole("scanner"))
	assert.False(t, isValidRole("invalid"))
	assert.False(t, isValidRole(""))
}

func TestIsValidTenantID(t *testing.T) {
	assert.True(t, isValidTenantID("valid-tenant-id"))
	assert.True(t, isValidTenantID("tenant123"))
	assert.False(t, isValidTenantID(""))
	assert.False(t, isValidTenantID("invalid@tenant"))
	assert.False(t, isValidTenantID("tenant with spaces"))
}

func TestMarshalUnmarshalJSON(t *testing.T) {
	original := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
		"key3": true,
	}

	// Marshal
	jsonStr, err := marshalJSON(original)
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonStr)

	// Unmarshal
	var result map[string]interface{}
	err = unmarshalJSON(jsonStr, &result)
	assert.NoError(t, err)
	assert.Equal(t, "value1", result["key1"])
	assert.Equal(t, float64(123), result["key2"]) // JSON numbers become float64
	assert.Equal(t, true, result["key3"])
}

func TestValidateTenant(t *testing.T) {
	tm, cleanup := setupTestTenantManager(t)
	defer cleanup()

	// Valid tenant
	validTenant := &Tenant{
		Name:   "Valid Tenant",
		Domain: "valid.com",
	}
	err := tm.validateTenant(validTenant)
	assert.NoError(t, err)

	// Invalid tenant - empty name
	invalidTenant := &Tenant{
		Name:   "",
		Domain: "test.com",
	}
	err = tm.validateTenant(invalidTenant)
	assert.Error(t, err)
}
