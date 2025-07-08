-- Migration: 000_create_migration_table.sql
-- Description: Create migration tracking table
-- Version: 0.0.1
-- Date: 2024-12-19

-- Create schema_migrations table to track applied migrations
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checksum TEXT
);

-- Insert initial migration record
INSERT OR IGNORE INTO schema_migrations (version, description, applied_at) 
VALUES ('000', 'Create migration tracking table', CURRENT_TIMESTAMP); 