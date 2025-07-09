package models

import (
	"encoding/json"
	"strings"
	"time"
)

// SBOM represents Software Bill of Materials
type SBOM struct {
	ID             int       `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	RepoName       string    `json:"repo_name" gorm:"column:repo_name"`
	ModulePath     string    `json:"module_path" gorm:"column:module_path"`
	ScanDate       time.Time `json:"scan_date" gorm:"column:scan_date"`
	SyftVersion    string    `json:"syft_version" gorm:"column:syft_version"`
	RawSBOM        string    `json:"raw_sbom" gorm:"column:raw_sbom"`
	ComponentCount int       `json:"component_count" gorm:"column:component_count"`
	CreatedAt      time.Time `json:"created_at" gorm:"column:created_at"`
	UpdatedAt      time.Time `json:"updated_at" gorm:"column:updated_at"`
}

// Component represents a software component in SBOM
type Component struct {
	ID            int                 `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	SBOMID        int                 `json:"sbom_id" gorm:"column:sbom_id"`
	Name          string              `json:"name" gorm:"column:name"`
	Version       string              `json:"version" gorm:"column:version"`
	Type          string              `json:"type" gorm:"column:type"` // library, application, container, etc.
	PURL          string              `json:"purl" gorm:"column:purl"` // Package URL
	CPE           string              `json:"cpe" gorm:"column:cpe"`   // Common Platform Enumeration
	Language      string              `json:"language" gorm:"column:language"`
	Licenses      []string            `json:"licenses" gorm:"-"`
	LicensesJSON  string              `json:"-" gorm:"column:licenses_json"`
	Locations     []ComponentLocation `json:"locations" gorm:"-"`
	LocationsJSON string              `json:"-" gorm:"column:locations_json"`
	Metadata      map[string]any      `json:"metadata" gorm:"-"`
	MetadataJSON  string              `json:"-" gorm:"column:metadata_json"`
	CreatedAt     time.Time           `json:"created_at" gorm:"column:created_at"`
	UpdatedAt     time.Time           `json:"updated_at" gorm:"column:updated_at"`
}

// ComponentLocation represents where a component is found
type ComponentLocation struct {
	Path      string `json:"path"`
	LayerID   string `json:"layer_id,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// SyftOutput represents the output structure from Syft tool
type SyftOutput struct {
	Schema    SyftSchema     `json:"schema"`
	Distro    SyftDistro     `json:"distro"`
	Source    SyftSource     `json:"source"`
	Artifacts []SyftArtifact `json:"artifacts"`
}

type SyftSchema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type SyftDistro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	IDLike  string `json:"idLike"`
}

type SyftSource struct {
	Type     string         `json:"type"`
	Target   string         `json:"target"`
	Metadata map[string]any `json:"metadata"`
}

type SyftArtifact struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Type        string          `json:"type"`
	PURL        string          `json:"purl"`
	CPEs        []SyftCPE       `json:"cpes"`
	Language    string          `json:"language"`
	Licenses    []string        `json:"-"` // Custom handling
	LicensesRaw json.RawMessage `json:"licenses"`
	Locations   []SyftLocation  `json:"locations"`
	Metadata    map[string]any  `json:"metadata"`
}

// UnmarshalLicenses parses the various license formats from Syft
func (s *SyftArtifact) UnmarshalLicenses() []string {
	if len(s.LicensesRaw) == 0 {
		return []string{}
	}

	// Try parsing as array of strings first
	var stringArray []string
	if err := json.Unmarshal(s.LicensesRaw, &stringArray); err == nil {
		// Clean and filter valid licenses
		var validLicenses []string
		for _, license := range stringArray {
			license = strings.TrimSpace(license)
			if license != "" && license != "null" && license != "NOASSERTION" && license != "UNKNOWN" {
				validLicenses = append(validLicenses, license)
			}
		}
		return validLicenses
	}

	// Try parsing as array of objects
	var objectArray []map[string]any
	if err := json.Unmarshal(s.LicensesRaw, &objectArray); err == nil {
		var licenses []string
		for _, obj := range objectArray {
			if name, ok := obj["name"].(string); ok && name != "" {
				name = strings.TrimSpace(name)
				if name != "null" && name != "NOASSERTION" && name != "UNKNOWN" {
					licenses = append(licenses, name)
				}
			}
			if id, ok := obj["id"].(string); ok && id != "" {
				id = strings.TrimSpace(id)
				if id != "null" && id != "NOASSERTION" && id != "UNKNOWN" {
					licenses = append(licenses, id)
				}
			}
			if value, ok := obj["value"].(string); ok && value != "" {
				value = strings.TrimSpace(value)
				if value != "null" && value != "NOASSERTION" && value != "UNKNOWN" {
					licenses = append(licenses, value)
				}
			}
		}
		return licenses
	}

	// Try parsing as single string
	var singleString string
	if err := json.Unmarshal(s.LicensesRaw, &singleString); err == nil {
		singleString = strings.TrimSpace(singleString)
		if singleString != "" && singleString != "null" && singleString != "NOASSERTION" && singleString != "UNKNOWN" {
			return []string{singleString}
		}
	}

	return []string{}
}

type SyftCPE struct {
	CPE    string `json:"cpe"`
	Source string `json:"source"`
}

type SyftLocation struct {
	Path      string `json:"path"`
	LayerID   string `json:"layerID,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// MarshalComponentFields marshals slice and map fields to JSON for database storage
func (c *Component) MarshalComponentFields() error {
	if len(c.Licenses) > 0 {
		licensesJSON, err := json.Marshal(c.Licenses)
		if err != nil {
			return err
		}
		c.LicensesJSON = string(licensesJSON)
	}

	if len(c.Locations) > 0 {
		locationsJSON, err := json.Marshal(c.Locations)
		if err != nil {
			return err
		}
		c.LocationsJSON = string(locationsJSON)
	}

	if len(c.Metadata) > 0 {
		metadataJSON, err := json.Marshal(c.Metadata)
		if err != nil {
			return err
		}
		c.MetadataJSON = string(metadataJSON)
	}

	return nil
}

// UnmarshalComponentFields unmarshals JSON fields back to slices and maps
func (c *Component) UnmarshalComponentFields() error {
	if c.LicensesJSON != "" {
		if err := json.Unmarshal([]byte(c.LicensesJSON), &c.Licenses); err != nil {
			return err
		}
	}

	if c.LocationsJSON != "" {
		if err := json.Unmarshal([]byte(c.LocationsJSON), &c.Locations); err != nil {
			return err
		}
	}

	if c.MetadataJSON != "" {
		if err := json.Unmarshal([]byte(c.MetadataJSON), &c.Metadata); err != nil {
			return err
		}
	}

	return nil
}
