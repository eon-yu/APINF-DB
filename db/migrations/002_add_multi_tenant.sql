-- Migration: 002_add_multi_tenant.sql
-- Description: Add multi-tenant support tables
-- Version: 1.1.0
-- Date: 2024-12-19

-- Multi-tenant tables
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    domain TEXT,
    settings TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tenant_users (
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer', 'scanner')),
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    PRIMARY KEY (user_id, tenant_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tenant_resources (
    resource_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('repository', 'module')),
    resource_name TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Multi-tenant indexes
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant_id ON tenant_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_users_user_id ON tenant_users(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_resources_tenant_id ON tenant_resources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_resources_type_name ON tenant_resources(resource_type, resource_name);

-- Multi-tenant triggers
CREATE TRIGGER IF NOT EXISTS trigger_tenants_updated_at 
    AFTER UPDATE ON tenants
    BEGIN
        UPDATE tenants SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS trigger_tenant_resources_updated_at 
    AFTER UPDATE ON tenant_resources
    BEGIN
        UPDATE tenant_resources SET updated_at = CURRENT_TIMESTAMP WHERE resource_id = NEW.resource_id;
    END;

-- Insert migration record
INSERT OR IGNORE INTO schema_migrations (version, description, applied_at) 
VALUES ('002', 'Add multi-tenant support tables', CURRENT_TIMESTAMP); 