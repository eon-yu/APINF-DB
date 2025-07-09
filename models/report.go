package models

import (
	"encoding/json"
	"time"
)

// Report represents a generated report
type Report struct {
	ID          int        `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	Title       string     `json:"title" gorm:"column:title"`
	Type        string     `json:"type" gorm:"column:type"`     // pdf, csv, excel
	Status      string     `json:"status" gorm:"column:status"` // generating, completed, failed
	Format      string     `json:"format" gorm:"column:format"` // summary, detailed, executive
	FilePath    string     `json:"file_path" gorm:"column:file_path"`
	FileSize    int64      `json:"file_size" gorm:"column:file_size"`
	GeneratedBy string     `json:"generated_by" gorm:"column:generated_by"`
	CreatedAt   time.Time  `json:"created_at" gorm:"column:created_at"`
	CompletedAt *time.Time `json:"completed_at" gorm:"column:completed_at"`

	// Report configuration
	ReportConfig ReportConfig `json:"report_config" gorm:"-"`

	// Metadata
	MetadataJSON string         `json:"-" gorm:"column:metadata_json"`
	Metadata     map[string]any `json:"metadata" gorm:"-"`
}

// ReportConfig holds the configuration for report generation
type ReportConfig struct {
	DateFrom          string   `json:"date_from"`
	DateTo            string   `json:"date_to"`
	Repositories      []string `json:"repositories"`
	ReportType        string   `json:"report_type"` // pdf, csv, excel
	IncludeVulns      bool     `json:"include_vulns"`
	IncludeLicense    bool     `json:"include_license"`
	IncludeComponents bool     `json:"include_components"`
	SeverityFilter    string   `json:"severity_filter"`
	IncludeCharts     bool     `json:"include_charts"`
}

// ReportSummary contains summary data for the report
type ReportSummary struct {
	TotalRepositories    int                    `json:"total_repositories"`
	TotalSBOMs           int                    `json:"total_sboms"`
	TotalComponents      int                    `json:"total_components"`
	TotalVulns           int                    `json:"total_vulnerabilities"`
	VulnsBySeverity      map[string]int         `json:"vulnerabilities_by_severity"`
	LicenseDistribution  map[string]int         `json:"license_distribution"`
	LanguageDistribution map[string]int         `json:"language_distribution"`
	RiskDistribution     map[string]int         `json:"risk_distribution"`
	TopVulnerableRepos   []VulnerableRepository `json:"top_vulnerable_repos"`
	TopLicenseIssues     []LicenseIssue         `json:"top_license_issues"`
}

// VulnerableRepository represents a repository with vulnerability stats
type VulnerableRepository struct {
	RepoName       string    `json:"repo_name"`
	TotalVulns     int       `json:"total_vulnerabilities"`
	CriticalVulns  int       `json:"critical_vulnerabilities"`
	HighVulns      int       `json:"high_vulnerabilities"`
	ComponentCount int       `json:"component_count"`
	LastScanDate   time.Time `json:"last_scan_date"`
}

// LicenseIssue represents a license compliance issue
type LicenseIssue struct {
	LicenseName   string   `json:"license_name"`
	IssueCount    int      `json:"issue_count"`
	Action        string   `json:"action"`
	AffectedRepos []string `json:"affected_repos"`
}

// ReportData contains all data needed for report generation
type ReportData struct {
	Summary      ReportSummary      `json:"summary"`
	Repositories []RepositoryReport `json:"repositories"`
	TotalScans   int                `json:"total_scans"`
	ScanPeriod   string             `json:"scan_period"`
	GeneratedAt  time.Time          `json:"generated_at"`
}

// RepositoryReport contains detailed data for each repository
type RepositoryReport struct {
	RepoName        string                `json:"repo_name"`
	ModuleCount     int                   `json:"module_count"`
	TotalComponents int                   `json:"total_components"`
	TotalVulns      int                   `json:"total_vulnerabilities"`
	VulnsBySeverity map[string]int        `json:"vulnerabilities_by_severity"`
	RiskLevel       string                `json:"risk_level"`
	LastScanDate    time.Time             `json:"last_scan_date"`
	Modules         []ModuleReport        `json:"modules"`
	TopVulns        []VulnerabilityReport `json:"top_vulnerabilities"`
	LicenseIssues   []LicenseIssue        `json:"license_issues"`
}

// ModuleReport contains data for each module within a repository
type ModuleReport struct {
	ModulePath      string         `json:"module_path"`
	Language        string         `json:"language"`
	PackageManager  string         `json:"package_manager"`
	ComponentCount  int            `json:"component_count"`
	VulnCount       int            `json:"vulnerability_count"`
	VulnsBySeverity map[string]int `json:"vulnerabilities_by_severity"`
	RiskLevel       string         `json:"risk_level"`
	ScanDate        time.Time      `json:"scan_date"`
}

// VulnerabilityReport represents a vulnerability in the report
type VulnerabilityReport struct {
	VulnID           string    `json:"vulnerability_id"`
	Severity         string    `json:"severity"`
	CVSS3Score       float64   `json:"cvss3_score"`
	Description      string    `json:"description"`
	ComponentName    string    `json:"component_name"`
	ComponentVersion string    `json:"component_version"`
	RepoName         string    `json:"repo_name"`
	PublishedDate    time.Time `json:"published_date"`
	FixAvailable     bool      `json:"fix_available"`
}

// MarshalReportFields marshals the ReportConfig and Metadata into JSON strings for database storage
func (r *Report) MarshalReportFields() error {
	// Marshal ReportConfig
	configJSON, err := json.Marshal(r.ReportConfig)
	if err != nil {
		return err
	}

	// Store config in metadata for now (could add separate column if needed)
	if r.Metadata == nil {
		r.Metadata = make(map[string]any)
	}
	r.Metadata["config"] = string(configJSON)

	// Marshal Metadata
	metadataJSON, err := json.Marshal(r.Metadata)
	if err != nil {
		return err
	}
	r.MetadataJSON = string(metadataJSON)

	return nil
}

// UnmarshalReportFields unmarshals the JSON strings from database into structured fields
func (r *Report) UnmarshalReportFields() error {
	// Unmarshal Metadata
	if r.MetadataJSON != "" {
		if err := json.Unmarshal([]byte(r.MetadataJSON), &r.Metadata); err != nil {
			return err
		}

		// Extract ReportConfig from metadata
		if configStr, ok := r.Metadata["config"].(string); ok {
			if err := json.Unmarshal([]byte(configStr), &r.ReportConfig); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetFileExtension returns the file extension for the report type
func (r *Report) GetFileExtension() string {
	switch r.Type {
	case "pdf":
		return ".pdf"
	case "csv":
		return ".csv"
	case "excel":
		return ".xlsx"
	default:
		return ".pdf"
	}
}

// GetFileName generates a filename for the report
func (r *Report) GetFileName() string {
	timestamp := r.CreatedAt.Format("20060102_150405")
	return r.Title + "_" + timestamp + r.GetFileExtension()
}
