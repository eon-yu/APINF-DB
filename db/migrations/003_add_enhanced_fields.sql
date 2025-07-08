-- Migration: 003_add_enhanced_fields.sql
-- Description: Add enhanced fields for C/C++ support, multi-module and web UI improvements
-- Version: 1.2.0
-- Date: 2024-12-19

-- Add new columns to sboms table
ALTER TABLE sboms ADD COLUMN vulnerability_count INTEGER DEFAULT 0;
ALTER TABLE sboms ADD COLUMN critical_count INTEGER DEFAULT 0;
ALTER TABLE sboms ADD COLUMN high_count INTEGER DEFAULT 0;
ALTER TABLE sboms ADD COLUMN medium_count INTEGER DEFAULT 0;
ALTER TABLE sboms ADD COLUMN low_count INTEGER DEFAULT 0;
ALTER TABLE sboms ADD COLUMN overall_risk_level TEXT DEFAULT 'low';
ALTER TABLE sboms ADD COLUMN is_multi_module BOOLEAN DEFAULT FALSE;
ALTER TABLE sboms ADD COLUMN module_type TEXT DEFAULT 'single';
ALTER TABLE sboms ADD COLUMN language TEXT;
ALTER TABLE sboms ADD COLUMN package_manager TEXT;

-- Add new columns to components table
ALTER TABLE components ADD COLUMN ecosystem TEXT;
ALTER TABLE components ADD COLUMN vulnerability_count INTEGER DEFAULT 0;

-- Add new columns to scan_results table
ALTER TABLE scan_results ADD COLUMN scan_duration_seconds INTEGER DEFAULT 0;
ALTER TABLE scan_results ADD COLUMN language TEXT;
ALTER TABLE scan_results ADD COLUMN package_manager TEXT;

-- Add scan jobs table for queue management
CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    repo_name TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    module_path TEXT,
    scan_type TEXT NOT NULL,     -- syft, grype, both
    status TEXT NOT NULL,        -- pending, running, completed, failed, cancelled
    progress INTEGER DEFAULT 0,  -- 0-100
    message TEXT,
    error_message TEXT,
    started_at DATETIME,
    completed_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Add new indexes for enhanced performance
CREATE INDEX IF NOT EXISTS idx_sboms_language ON sboms(language);
CREATE INDEX IF NOT EXISTS idx_sboms_package_manager ON sboms(package_manager);
CREATE INDEX IF NOT EXISTS idx_sboms_module_type ON sboms(module_type);
CREATE INDEX IF NOT EXISTS idx_sboms_risk_level ON sboms(overall_risk_level);
CREATE INDEX IF NOT EXISTS idx_components_language ON components(language);
CREATE INDEX IF NOT EXISTS idx_components_ecosystem ON components(ecosystem);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss3 ON vulnerabilities(cvss3_score DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
CREATE INDEX IF NOT EXISTS idx_scan_results_language ON scan_results(language);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);

-- Add trigger for scan_jobs
CREATE TRIGGER IF NOT EXISTS trigger_scan_jobs_updated_at 
    AFTER UPDATE ON scan_jobs
    BEGIN
        UPDATE scan_jobs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

-- Create views for better data access
CREATE VIEW IF NOT EXISTS v_sbom_summary AS
SELECT 
    s.id,
    s.repo_name,
    s.module_path,
    s.scan_date,
    s.component_count,
    s.vulnerability_count,
    s.critical_count,
    s.high_count,
    s.medium_count,
    s.low_count,
    s.overall_risk_level,
    s.is_multi_module,
    s.module_type,
    s.language,
    s.package_manager,
    COUNT(DISTINCT c.id) as actual_component_count,
    COUNT(DISTINCT v.id) as actual_vulnerability_count
FROM sboms s
LEFT JOIN components c ON s.id = c.sbom_id
LEFT JOIN vulnerabilities v ON c.id = v.component_id
GROUP BY s.id;

CREATE VIEW IF NOT EXISTS v_vulnerability_summary AS
SELECT 
    v.id,
    v.vuln_id,
    v.severity,
    v.cvss3_score,
    c.name as component_name,
    c.version as component_version,
    c.language as component_language,
    s.repo_name,
    s.module_path,
    s.scan_date
FROM vulnerabilities v
JOIN components c ON v.component_id = c.id
JOIN sboms s ON c.sbom_id = s.id;

-- Insert initial data for license policies
INSERT OR IGNORE INTO license_policies (license_name, action, reason, is_active) VALUES
('GPL-2.0', 'block', 'Copyleft license - requires source code disclosure', 1),
('GPL-3.0', 'block', 'Copyleft license - requires source code disclosure', 1),
('AGPL-3.0', 'block', 'Network copyleft license - requires source code disclosure', 1),
('LGPL-2.1', 'warn', 'Lesser copyleft license - review required', 1),
('LGPL-3.0', 'warn', 'Lesser copyleft license - review required', 1),
('MIT', 'allow', 'Permissive license - safe to use', 1),
('Apache-2.0', 'allow', 'Permissive license - safe to use', 1),
('BSD-2-Clause', 'allow', 'Permissive license - safe to use', 1),
('BSD-3-Clause', 'allow', 'Permissive license - safe to use', 1),
('ISC', 'allow', 'Permissive license - safe to use', 1),
('Unlicense', 'allow', 'Public domain - safe to use', 1);

-- Insert initial data for vulnerability policies
INSERT OR IGNORE INTO vulnerability_policies (min_severity_level, max_cvss_score, action, ignore_fix_available, grace_period_days, is_active) VALUES
('Critical', 9.0, 'block', 0, 0, 1),
('High', 7.0, 'warn', 0, 7, 1),
('Medium', 4.0, 'allow', 1, 30, 1),
('Low', 0.0, 'allow', 1, 90, 1);

-- Insert migration record
INSERT OR IGNORE INTO schema_migrations (version, description, applied_at) 
VALUES ('003', 'Add enhanced fields for C/C++ support, multi-module and web UI improvements', CURRENT_TIMESTAMP); 