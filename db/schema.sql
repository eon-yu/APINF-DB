-- OSS Compliance Scanner Database Schema
-- SQLite3 compatible
-- Updated: 2024-12-19 - Added C/C++ support, multi-module enhancements, web UI improvements

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
    vulnerability_count INTEGER DEFAULT 0,    -- 추가: 취약점 수 저장
    critical_count INTEGER DEFAULT 0,         -- 추가: Critical 취약점 수
    high_count INTEGER DEFAULT 0,             -- 추가: High 취약점 수
    medium_count INTEGER DEFAULT 0,           -- 추가: Medium 취약점 수
    low_count INTEGER DEFAULT 0,              -- 추가: Low 취약점 수
    overall_risk_level TEXT DEFAULT 'low',    -- 추가: 전체 위험도 (low, medium, high, critical)
    is_multi_module BOOLEAN DEFAULT FALSE,    -- 추가: 멀티 모듈 여부
    module_type TEXT DEFAULT 'single',        -- 추가: 모듈 타입 (single, multi, root)
    language TEXT,                            -- 추가: 주요 언어
    package_manager TEXT,                     -- 추가: 패키지 매니저 (npm, go, pip, maven, cmake, conan, vcpkg 등)
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
    type TEXT NOT NULL,     -- library, application, container, etc.
    purl TEXT,              -- Package URL
    cpe TEXT,               -- Common Platform Enumeration
    language TEXT,          -- 언어 정보 (cpp, c, go, javascript, python, java, rust, php, ruby, etc.)
    ecosystem TEXT,         -- 생태계 (npm, go, pypi, maven, conan, vcpkg, etc.)
    licenses_json TEXT,     -- JSON array of licenses
    locations_json TEXT,    -- JSON array of locations
    metadata_json TEXT,     -- JSON metadata
    vulnerability_count INTEGER DEFAULT 0,    -- 추가: 해당 컴포넌트의 취약점 수
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE,
    UNIQUE(sbom_id, name, version, type)
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    vuln_id TEXT NOT NULL,        -- CVE-2023-1234
    severity TEXT NOT NULL,       -- Critical, High, Medium, Low
    cvss3_score REAL DEFAULT 0.0,
    cvss2_score REAL DEFAULT 0.0,
    description TEXT,
    published_date DATETIME,
    modified_date DATETIME,
    urls_json TEXT,              -- JSON array of URLs
    fixes_json TEXT,             -- JSON array of fix information
    metadata_json TEXT,          -- JSON metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
    UNIQUE(component_id, vuln_id)
);

-- License policies table
CREATE TABLE IF NOT EXISTS license_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_name TEXT UNIQUE NOT NULL,
    action TEXT NOT NULL,        -- allow, warn, block, fail
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
    action TEXT NOT NULL,        -- allow, warn, block, fail
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
    vulnerability_id INTEGER,    -- NULL for license violations
    violation_type TEXT NOT NULL, -- license, vulnerability
    severity TEXT NOT NULL,
    policy_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    recommended_action TEXT,
    status TEXT DEFAULT 'open',  -- open, ignored, resolved, false_positive
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
    status TEXT NOT NULL,        -- pending, running, completed, failed, cancelled
    total_components INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    license_violations INTEGER DEFAULT 0,
    critical_vulns INTEGER DEFAULT 0,
    high_vulns INTEGER DEFAULT 0,
    medium_vulns INTEGER DEFAULT 0,
    low_vulns INTEGER DEFAULT 0,
    overall_risk TEXT,           -- low, medium, high, critical
    scan_duration_seconds INTEGER DEFAULT 0,  -- 추가: 스캔 소요 시간
    language TEXT,               -- 추가: 주요 언어
    package_manager TEXT,        -- 추가: 패키지 매니저
    metadata_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
);

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

-- 추가: 스캔 작업 큐 테이블
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

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sboms_repo_module ON sboms(repo_name, module_path);
CREATE INDEX IF NOT EXISTS idx_sboms_scan_date ON sboms(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_sboms_language ON sboms(language);
CREATE INDEX IF NOT EXISTS idx_sboms_package_manager ON sboms(package_manager);
CREATE INDEX IF NOT EXISTS idx_sboms_module_type ON sboms(module_type);
CREATE INDEX IF NOT EXISTS idx_sboms_risk_level ON sboms(overall_risk_level);

CREATE INDEX IF NOT EXISTS idx_components_sbom_id ON components(sbom_id);
CREATE INDEX IF NOT EXISTS idx_components_name_version ON components(name, version);
CREATE INDEX IF NOT EXISTS idx_components_language ON components(language);
CREATE INDEX IF NOT EXISTS idx_components_ecosystem ON components(ecosystem);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_component_id ON vulnerabilities(component_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vuln_id ON vulnerabilities(vuln_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss3 ON vulnerabilities(cvss3_score DESC);

CREATE INDEX IF NOT EXISTS idx_policy_violations_sbom_id ON policy_violations(sbom_id);
CREATE INDEX IF NOT EXISTS idx_policy_violations_status ON policy_violations(status);
CREATE INDEX IF NOT EXISTS idx_policy_violations_type ON policy_violations(violation_type);

CREATE INDEX IF NOT EXISTS idx_scan_results_repo_module ON scan_results(repo_name, module_path);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan_time ON scan_results(scan_start_time DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
CREATE INDEX IF NOT EXISTS idx_scan_results_language ON scan_results(language);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at ON scan_jobs(created_at DESC);

-- Multi-tenant indexes
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant_id ON tenant_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_users_user_id ON tenant_users(user_id);
CREATE INDEX IF NOT EXISTS idx_tenant_resources_tenant_id ON tenant_resources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_resources_type_name ON tenant_resources(resource_type, resource_name);

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

CREATE TRIGGER IF NOT EXISTS trigger_scan_jobs_updated_at 
    AFTER UPDATE ON scan_jobs
    BEGIN
        UPDATE scan_jobs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

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

-- Views for better data access
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

-- 초기 데이터 삽입 (라이선스 정책)
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

-- 초기 데이터 삽입 (취약점 정책)
INSERT OR IGNORE INTO vulnerability_policies (min_severity_level, max_cvss_score, action, ignore_fix_available, grace_period_days, is_active) VALUES
('Critical', 9.0, 'block', 0, 0, 1),
('High', 7.0, 'warn', 0, 7, 1),
('Medium', 4.0, 'allow', 1, 30, 1),
('Low', 0.0, 'allow', 1, 90, 1);

-- 데이터베이스 버전 정보
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

INSERT OR REPLACE INTO schema_version (version, description) VALUES
('1.0.0', 'Initial schema with basic SBOM, components, and vulnerabilities'),
('1.1.0', 'Added multi-tenant support'),
('1.2.0', 'Added C/C++ support, multi-module enhancements, web UI improvements'); 