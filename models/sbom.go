package models

import (
	"encoding/json"
	"time"
)

// SBOM represents Software Bill of Materials
type SBOM struct {
	ID             int       `json:"id" db:"id"`
	RepoName       string    `json:"repo_name" db:"repo_name"`
	ModulePath     string    `json:"module_path" db:"module_path"`
	ScanDate       time.Time `json:"scan_date" db:"scan_date"`
	SyftVersion    string    `json:"syft_version" db:"syft_version"`
	RawSBOM        string    `json:"raw_sbom" db:"raw_sbom"`
	ComponentCount int       `json:"component_count" db:"component_count"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// Component represents a software component in SBOM
type Component struct {
	ID            int                    `json:"id" db:"id"`
	SBOMID        int                    `json:"sbom_id" db:"sbom_id"`
	Name          string                 `json:"name" db:"name"`
	Version       string                 `json:"version" db:"version"`
	Type          string                 `json:"type" db:"type"` // library, application, container, etc.
	PURL          string                 `json:"purl" db:"purl"` // Package URL
	CPE           string                 `json:"cpe" db:"cpe"`   // Common Platform Enumeration
	Language      string                 `json:"language" db:"language"`
	Licenses      []string               `json:"licenses" db:"-"`
	LicensesJSON  string                 `json:"-" db:"licenses_json"`
	Locations     []ComponentLocation    `json:"locations" db:"-"`
	LocationsJSON string                 `json:"-" db:"locations_json"`
	Metadata      map[string]interface{} `json:"metadata" db:"-"`
	MetadataJSON  string                 `json:"-" db:"metadata_json"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" db:"updated_at"`
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
	Type     string                 `json:"type"`
	Target   string                 `json:"target"`
	Metadata map[string]interface{} `json:"metadata"`
}

type SyftArtifact struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Version   string                 `json:"version"`
	Type      string                 `json:"type"`
	PURL      string                 `json:"purl"`
	CPEs      []SyftCPE              `json:"cpes"`
	Language  string                 `json:"language"`
	Licenses  []string               `json:"licenses"`
	Locations []SyftLocation         `json:"locations"`
	Metadata  map[string]interface{} `json:"metadata"`
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
