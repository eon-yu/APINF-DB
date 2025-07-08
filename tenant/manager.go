package tenant

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"oss-compliance-scanner/db"
	"oss-compliance-scanner/models"
)

// Tenant represents an organization or team
type Tenant struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Description string                 `json:"description" db:"description"`
	Domain      string                 `json:"domain" db:"domain"` // email domain for auto-assignment
	Settings    TenantSettings         `json:"settings" db:"settings"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	IsActive    bool                   `json:"is_active" db:"is_active"`
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
}

// TenantSettings holds tenant-specific configuration
type TenantSettings struct {
	DefaultPolicies      TenantPolicies `json:"default_policies"`
	NotificationSettings struct {
		SlackWebhookURL   string   `json:"slack_webhook_url"`
		EmailRecipients   []string `json:"email_recipients"`
		NotifyOnScan      bool     `json:"notify_on_scan"`
		NotifyOnViolation bool     `json:"notify_on_violation"`
	} `json:"notification_settings"`
	ScanSettings struct {
		AutoScanEnabled   bool     `json:"auto_scan_enabled"`
		ScanSchedule      string   `json:"scan_schedule"` // cron format
		AllowedRepos      []string `json:"allowed_repos"`
		RestrictedModules []string `json:"restricted_modules"`
	} `json:"scan_settings"`
	CustomRules []string `json:"custom_rules"` // paths to custom rule files
}

// TenantPolicies holds tenant-specific policy overrides
type TenantPolicies struct {
	LicensePolicies       []models.LicensePolicy       `json:"license_policies"`
	VulnerabilityPolicies []models.VulnerabilityPolicy `json:"vulnerability_policies"`
	GlobalSettings        models.GlobalPolicySettings  `json:"global_settings"`
}

// TenantUser represents a user associated with a tenant
type TenantUser struct {
	UserID    string    `json:"user_id" db:"user_id"`
	TenantID  string    `json:"tenant_id" db:"tenant_id"`
	Role      string    `json:"role" db:"role"` // admin, viewer, scanner
	Email     string    `json:"email" db:"email"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	IsActive  bool      `json:"is_active" db:"is_active"`
}

// TenantResource represents a resource (repo/module) owned by a tenant
type TenantResource struct {
	ResourceID   string    `json:"resource_id" db:"resource_id"`
	TenantID     string    `json:"tenant_id" db:"tenant_id"`
	ResourceType string    `json:"resource_type" db:"resource_type"` // repository, module
	ResourceName string    `json:"resource_name" db:"resource_name"`
	Path         string    `json:"path" db:"path"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	IsActive     bool      `json:"is_active" db:"is_active"`
}

// TenantManager manages multi-tenant operations
type TenantManager struct {
	database *db.Database
}

// NewTenantManager creates a new tenant manager
func NewTenantManager(database *db.Database) *TenantManager {
	return &TenantManager{
		database: database,
	}
}

// CreateTenant creates a new tenant
func (tm *TenantManager) CreateTenant(tenant *Tenant) error {
	if tenant.ID == "" {
		tenant.ID = generateTenantID(tenant.Name)
	}

	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = time.Now()
	tenant.IsActive = true

	// Validate tenant
	if err := tm.validateTenant(tenant); err != nil {
		return fmt.Errorf("invalid tenant: %w", err)
	}

	// Initialize schema for tenant if needed
	if err := tm.initializeTenantSchema(tenant.ID); err != nil {
		return fmt.Errorf("failed to initialize tenant schema: %w", err)
	}

	// Insert tenant record
	query := `
		INSERT INTO tenants (id, name, description, domain, settings, created_at, updated_at, is_active, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	settingsJSON, _ := marshalJSON(tenant.Settings)
	metadataJSON, _ := marshalJSON(tenant.Metadata)

	_, err := tm.database.Exec(query, tenant.ID, tenant.Name, tenant.Description,
		tenant.Domain, settingsJSON, tenant.CreatedAt, tenant.UpdatedAt,
		tenant.IsActive, metadataJSON)

	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// GetTenant retrieves a tenant by ID
func (tm *TenantManager) GetTenant(tenantID string) (*Tenant, error) {
	query := `
		SELECT id, name, description, domain, settings, created_at, updated_at, is_active, metadata
		FROM tenants WHERE id = ? AND is_active = 1
	`

	tenant := &Tenant{}
	var settingsJSON, metadataJSON string

	err := tm.database.QueryRow(query, tenantID).Scan(
		&tenant.ID, &tenant.Name, &tenant.Description, &tenant.Domain,
		&settingsJSON, &tenant.CreatedAt, &tenant.UpdatedAt, &tenant.IsActive,
		&metadataJSON,
	)

	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	// Unmarshal JSON fields
	unmarshalJSON(settingsJSON, &tenant.Settings)
	unmarshalJSON(metadataJSON, &tenant.Metadata)

	return tenant, nil
}

// GetTenantByDomain finds a tenant by email domain
func (tm *TenantManager) GetTenantByDomain(domain string) (*Tenant, error) {
	query := `
		SELECT id, name, description, domain, settings, created_at, updated_at, is_active, metadata
		FROM tenants WHERE domain = ? AND is_active = 1
	`

	tenant := &Tenant{}
	var settingsJSON, metadataJSON string

	err := tm.database.QueryRow(query, domain).Scan(
		&tenant.ID, &tenant.Name, &tenant.Description, &tenant.Domain,
		&settingsJSON, &tenant.CreatedAt, &tenant.UpdatedAt, &tenant.IsActive,
		&metadataJSON,
	)

	if err != nil {
		return nil, fmt.Errorf("tenant not found for domain %s: %w", domain, err)
	}

	unmarshalJSON(settingsJSON, &tenant.Settings)
	unmarshalJSON(metadataJSON, &tenant.Metadata)

	return tenant, nil
}

// ListTenants returns all active tenants
func (tm *TenantManager) ListTenants() ([]*Tenant, error) {
	query := `
		SELECT id, name, description, domain, settings, created_at, updated_at, is_active, metadata
		FROM tenants WHERE is_active = 1 ORDER BY name
	`

	rows, err := tm.database.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		tenant := &Tenant{}
		var settingsJSON, metadataJSON string

		err := rows.Scan(
			&tenant.ID, &tenant.Name, &tenant.Description, &tenant.Domain,
			&settingsJSON, &tenant.CreatedAt, &tenant.UpdatedAt, &tenant.IsActive,
			&metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant: %w", err)
		}

		unmarshalJSON(settingsJSON, &tenant.Settings)
		unmarshalJSON(metadataJSON, &tenant.Metadata)

		tenants = append(tenants, tenant)
	}

	return tenants, nil
}

// UpdateTenant updates an existing tenant
func (tm *TenantManager) UpdateTenant(tenant *Tenant) error {
	if err := tm.validateTenant(tenant); err != nil {
		return fmt.Errorf("invalid tenant: %w", err)
	}

	tenant.UpdatedAt = time.Now()

	query := `
		UPDATE tenants 
		SET name = ?, description = ?, domain = ?, settings = ?, updated_at = ?, metadata = ?
		WHERE id = ? AND is_active = 1
	`

	settingsJSON, _ := marshalJSON(tenant.Settings)
	metadataJSON, _ := marshalJSON(tenant.Metadata)

	_, err := tm.database.Exec(query, tenant.Name, tenant.Description, tenant.Domain,
		settingsJSON, tenant.UpdatedAt, metadataJSON, tenant.ID)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	return nil
}

// DeleteTenant soft deletes a tenant
func (tm *TenantManager) DeleteTenant(tenantID string) error {
	query := `UPDATE tenants SET is_active = 0, updated_at = ? WHERE id = ?`
	_, err := tm.database.Exec(query, time.Now(), tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}
	return nil
}

// User Management

// AddUserToTenant adds a user to a tenant with a specific role
func (tm *TenantManager) AddUserToTenant(tenantID, userID, email, name, role string) error {
	if !isValidRole(role) {
		return fmt.Errorf("invalid role: %s", role)
	}

	query := `
		INSERT INTO tenant_users (user_id, tenant_id, role, email, name, created_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(user_id, tenant_id) DO UPDATE SET
		role = ?, email = ?, name = ?, is_active = 1
	`

	now := time.Now()
	_, err := tm.database.Exec(query, userID, tenantID, role, email, name, now, role, email, name)
	if err != nil {
		return fmt.Errorf("failed to add user to tenant: %w", err)
	}

	return nil
}

// GetTenantUsers returns all users for a tenant
func (tm *TenantManager) GetTenantUsers(tenantID string) ([]*TenantUser, error) {
	query := `
		SELECT user_id, tenant_id, role, email, name, created_at, is_active
		FROM tenant_users WHERE tenant_id = ? AND is_active = 1
		ORDER BY name
	`

	rows, err := tm.database.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant users: %w", err)
	}
	defer rows.Close()

	var users []*TenantUser
	for rows.Next() {
		user := &TenantUser{}
		err := rows.Scan(&user.UserID, &user.TenantID, &user.Role, &user.Email,
			&user.Name, &user.CreatedAt, &user.IsActive)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	return users, nil
}

// GetUserTenants returns all tenants for a user
func (tm *TenantManager) GetUserTenants(userID string) ([]*Tenant, error) {
	query := `
		SELECT t.id, t.name, t.description, t.domain, t.settings, t.created_at, t.updated_at, t.is_active, t.metadata
		FROM tenants t
		JOIN tenant_users tu ON t.id = tu.tenant_id
		WHERE tu.user_id = ? AND t.is_active = 1 AND tu.is_active = 1
		ORDER BY t.name
	`

	rows, err := tm.database.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		tenant := &Tenant{}
		var settingsJSON, metadataJSON string

		err := rows.Scan(
			&tenant.ID, &tenant.Name, &tenant.Description, &tenant.Domain,
			&settingsJSON, &tenant.CreatedAt, &tenant.UpdatedAt, &tenant.IsActive,
			&metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant: %w", err)
		}

		unmarshalJSON(settingsJSON, &tenant.Settings)
		unmarshalJSON(metadataJSON, &tenant.Metadata)

		tenants = append(tenants, tenant)
	}

	return tenants, nil
}

// Resource Management

// AssignResourceToTenant assigns a repository or module to a tenant
func (tm *TenantManager) AssignResourceToTenant(tenantID, resourceType, resourceName, path string) error {
	resourceID := generateResourceID(resourceType, resourceName)

	query := `
		INSERT INTO tenant_resources (resource_id, tenant_id, resource_type, resource_name, path, created_at, updated_at, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(resource_id) DO UPDATE SET
		tenant_id = ?, updated_at = ?, is_active = 1
	`

	now := time.Now()
	_, err := tm.database.Exec(query, resourceID, tenantID, resourceType, resourceName, path, now, now, tenantID, now)
	if err != nil {
		return fmt.Errorf("failed to assign resource to tenant: %w", err)
	}

	return nil
}

// GetTenantResources returns all resources for a tenant
func (tm *TenantManager) GetTenantResources(tenantID string) ([]*TenantResource, error) {
	query := `
		SELECT resource_id, tenant_id, resource_type, resource_name, path, created_at, updated_at, is_active
		FROM tenant_resources WHERE tenant_id = ? AND is_active = 1
		ORDER BY resource_type, resource_name
	`

	rows, err := tm.database.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant resources: %w", err)
	}
	defer rows.Close()

	var resources []*TenantResource
	for rows.Next() {
		resource := &TenantResource{}
		err := rows.Scan(&resource.ResourceID, &resource.TenantID, &resource.ResourceType,
			&resource.ResourceName, &resource.Path, &resource.CreatedAt, &resource.UpdatedAt, &resource.IsActive)
		if err != nil {
			return nil, fmt.Errorf("failed to scan resource: %w", err)
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// GetResourceTenant returns the tenant that owns a resource
func (tm *TenantManager) GetResourceTenant(resourceType, resourceName string) (*Tenant, error) {
	resourceID := generateResourceID(resourceType, resourceName)

	query := `
		SELECT t.id, t.name, t.description, t.domain, t.settings, t.created_at, t.updated_at, t.is_active, t.metadata
		FROM tenants t
		JOIN tenant_resources tr ON t.id = tr.tenant_id
		WHERE tr.resource_id = ? AND t.is_active = 1 AND tr.is_active = 1
	`

	tenant := &Tenant{}
	var settingsJSON, metadataJSON string

	err := tm.database.QueryRow(query, resourceID).Scan(
		&tenant.ID, &tenant.Name, &tenant.Description, &tenant.Domain,
		&settingsJSON, &tenant.CreatedAt, &tenant.UpdatedAt, &tenant.IsActive,
		&metadataJSON,
	)

	if err != nil {
		return nil, fmt.Errorf("resource owner not found: %w", err)
	}

	unmarshalJSON(settingsJSON, &tenant.Settings)
	unmarshalJSON(metadataJSON, &tenant.Metadata)

	return tenant, nil
}

// Utility functions

func (tm *TenantManager) validateTenant(tenant *Tenant) error {
	if tenant.Name == "" {
		return fmt.Errorf("tenant name is required")
	}

	if tenant.ID == "" {
		return fmt.Errorf("tenant ID is required")
	}

	// Validate ID format (alphanumeric + hyphens only)
	if !isValidTenantID(tenant.ID) {
		return fmt.Errorf("invalid tenant ID format")
	}

	return nil
}

func (tm *TenantManager) initializeTenantSchema(tenantID string) error {
	// Create tenant-specific tables or schemas if needed
	// For SQLite, we can use table prefixes
	// For PostgreSQL, we could use schemas

	// This is a placeholder - implement based on your database strategy
	return nil
}

// Helper functions

func generateTenantID(name string) string {
	// Convert name to valid ID (lowercase, replace spaces with hyphens)
	id := strings.ToLower(name)
	id = strings.ReplaceAll(id, " ", "-")
	id = strings.ReplaceAll(id, "_", "-")

	// Add timestamp for uniqueness
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s-%d", id, timestamp)
}

func generateResourceID(resourceType, resourceName string) string {
	return fmt.Sprintf("%s:%s", resourceType, resourceName)
}

func isValidRole(role string) bool {
	validRoles := []string{"admin", "viewer", "scanner"}
	for _, validRole := range validRoles {
		if role == validRole {
			return true
		}
	}
	return false
}

func isValidTenantID(id string) bool {
	// Simple validation: alphanumeric characters and hyphens only
	for _, char := range id {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}
	return len(id) > 0
}

// JSON marshaling helpers
func marshalJSON(v interface{}) (string, error) {
	if v == nil {
		return "{}", nil
	}
	bytes, err := json.Marshal(v)
	if err != nil {
		return "{}", err
	}
	return string(bytes), nil
}

func unmarshalJSON(data string, v interface{}) error {
	if data == "" || data == "{}" {
		return nil
	}
	return json.Unmarshal([]byte(data), v)
}
