-- Migration: 001_initial_init.sql
-- Description: Initial database schema for OSS Compliance Scanner
-- Version: 1.0.0
-- Date: 2024-12-19

-- Enable foreign key support
PRAGMA foreign_keys = ON;

-- SBOM (Software Bill of Materials) table
CREATE TABLE IF NOT EXISTS sboms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_name TEXT NOT NULL,
    module_path TEXT NOT NULL,
    scan_date DATETIME NOT NULL,
    syft_version TEXT NOT NULL,
    raw_sbom TEXT NOT NULL,
    component_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(repo_name, module_path, scan_date)
);

-- Components table
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    type TEXT NOT NULL,
    purl TEXT,
    cpe TEXT,
    language TEXT,
    licenses_json TEXT,
    locations_json TEXT,
    metadata_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE,
    UNIQUE(sbom_id, name, version, type)
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    vuln_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss3_score REAL DEFAULT 0.0,
    cvss2_score REAL DEFAULT 0.0,
    description TEXT,
    published_date DATETIME,
    modified_date DATETIME,
    urls_json TEXT,
    fixes_json TEXT,
    metadata_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
    UNIQUE(component_id, vuln_id)
);

-- License policies table
CREATE TABLE IF NOT EXISTS license_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_name TEXT UNIQUE NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability policies table  
CREATE TABLE IF NOT EXISTS vulnerability_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    min_severity_level TEXT NOT NULL,
    max_cvss_score REAL NOT NULL,
    action TEXT NOT NULL,
    ignore_fix_available BOOLEAN DEFAULT FALSE,
    grace_period_days INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Policy violations table
CREATE TABLE IF NOT EXISTS policy_violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id INTEGER NOT NULL,
    component_id INTEGER NOT NULL,
    vulnerability_id INTEGER,
    violation_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    policy_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    recommended_action TEXT,
    status TEXT DEFAULT 'open',
    metadata_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE,
    FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- Scan results table
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id INTEGER NOT NULL,
    repo_name TEXT NOT NULL,
    module_path TEXT NOT NULL,
    scan_start_time DATETIME NOT NULL,
    scan_end_time DATETIME NOT NULL,
    status TEXT NOT NULL,
    total_components INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    license_violations INTEGER DEFAULT 0,
    critical_vulns INTEGER DEFAULT 0,
    high_vulns INTEGER DEFAULT 0,
    medium_vulns INTEGER DEFAULT 0,
    low_vulns INTEGER DEFAULT 0,
    overall_risk TEXT,
    metadata_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sboms_repo_module ON sboms(repo_name, module_path);
CREATE INDEX IF NOT EXISTS idx_sboms_scan_date ON sboms(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_components_sbom_id ON components(sbom_id);
CREATE INDEX IF NOT EXISTS idx_components_name_version ON components(name, version);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_component_id ON vulnerabilities(component_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vuln_id ON vulnerabilities(vuln_id);
CREATE INDEX IF NOT EXISTS idx_policy_violations_sbom_id ON policy_violations(sbom_id);
CREATE INDEX IF NOT EXISTS idx_policy_violations_status ON policy_violations(status);
CREATE INDEX IF NOT EXISTS idx_policy_violations_type ON policy_violations(violation_type);
CREATE INDEX IF NOT EXISTS idx_scan_results_repo_module ON scan_results(repo_name, module_path);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_time ON scan_results(scan_start_time DESC);

-- Triggers for updated_at timestamps
CREATE TRIGGER IF NOT EXISTS trigger_sboms_updated_at 
    AFTER UPDATE ON sboms
    BEGIN
        UPDATE sboms SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS trigger_components_updated_at 
    AFTER UPDATE ON components
    BEGIN
        UPDATE components SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS trigger_vulnerabilities_updated_at 
    AFTER UPDATE ON vulnerabilities
    BEGIN
        UPDATE vulnerabilities SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS trigger_license_policies_updated_at 
    AFTER UPDATE ON license_policies
    BEGIN
        UPDATE license_policies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS trigger_vulnerability_policies_updated_at 
    AFTER UPDATE ON vulnerability_policies
    BEGIN
        UPDATE vulnerability_policies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS trigger_policy_violations_updated_at 
    AFTER UPDATE ON policy_violations
    BEGIN
        UPDATE policy_violations SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS trigger_scan_results_updated_at 
    AFTER UPDATE ON scan_results
    BEGIN
        UPDATE scan_results SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

-- Insert initial migration record
INSERT OR IGNORE INTO schema_migrations (version, description, applied_at) 
VALUES ('001', 'Initial database schema', CURRENT_TIMESTAMP); 