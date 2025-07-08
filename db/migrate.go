package db

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"sort"
	"strings"
)

// Migration represents a database migration
type Migration struct {
	Version     string
	Description string
	SQL         string
	Applied     bool
}

// MigrationManager handles database migrations
type MigrationManager struct {
	db            *sql.DB
	migrationsDir string
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(db *sql.DB, migrationsDir string) *MigrationManager {
	return &MigrationManager{
		db:            db,
		migrationsDir: migrationsDir,
	}
}

// EnsureMigrationTable creates the schema_migrations table if it doesn't exist
func (m *MigrationManager) EnsureMigrationTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY,
		description TEXT NOT NULL,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		checksum TEXT
	)`

	_, err := m.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %v", err)
	}

	return nil
}

// GetAppliedMigrations returns a list of applied migrations
func (m *MigrationManager) GetAppliedMigrations() (map[string]bool, error) {
	applied := make(map[string]bool)

	rows, err := m.db.Query("SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("failed to scan migration version: %v", err)
		}
		applied[version] = true
	}

	return applied, nil
}

// LoadMigrations loads all migration files from the migrations directory
func (m *MigrationManager) LoadMigrations() ([]Migration, error) {
	files, err := filepath.Glob(filepath.Join(m.migrationsDir, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("failed to read migration files: %v", err)
	}

	// Sort files by name to ensure proper order
	sort.Strings(files)

	var migrations []Migration
	for _, file := range files {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read migration file %s: %v", file, err)
		}

		// Extract version from filename (e.g., 001_initial_schema.sql -> 001)
		filename := filepath.Base(file)
		parts := strings.Split(filename, "_")
		if len(parts) < 2 {
			log.Printf("Warning: migration file %s doesn't follow naming convention (XXX_description.sql)", filename)
			continue
		}

		version := parts[0]
		description := strings.TrimSuffix(strings.Join(parts[1:], "_"), ".sql")

		migrations = append(migrations, Migration{
			Version:     version,
			Description: description,
			SQL:         string(content),
		})
	}

	return migrations, nil
}

// ApplyMigration applies a single migration
func (m *MigrationManager) ApplyMigration(migration Migration) error {
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Execute migration SQL
	_, err = tx.Exec(migration.SQL)
	if err != nil {
		return fmt.Errorf("failed to execute migration %s: %v", migration.Version, err)
	}

	// Record migration as applied (if not already recorded in the migration SQL)
	_, err = tx.Exec(`
		INSERT OR IGNORE INTO schema_migrations (version, description, applied_at) 
		VALUES (?, ?, CURRENT_TIMESTAMP)`,
		migration.Version, migration.Description)
	if err != nil {
		return fmt.Errorf("failed to record migration %s: %v", migration.Version, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration %s: %v", migration.Version, err)
	}

	log.Printf("Applied migration %s: %s", migration.Version, migration.Description)
	return nil
}

// Migrate runs all pending migrations
func (m *MigrationManager) Migrate() error {
	// Ensure migration table exists
	if err := m.EnsureMigrationTable(); err != nil {
		return err
	}

	// Get applied migrations
	appliedMigrations, err := m.GetAppliedMigrations()
	if err != nil {
		return err
	}

	// Load available migrations
	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	// Apply pending migrations
	pendingCount := 0
	for _, migration := range migrations {
		if !appliedMigrations[migration.Version] {
			if err := m.ApplyMigration(migration); err != nil {
				return err
			}
			pendingCount++
		}
	}

	if pendingCount == 0 {
		log.Println("No pending migrations to apply")
	} else {
		log.Printf("Applied %d migrations successfully", pendingCount)
	}

	return nil
}

// GetMigrationStatus returns the current migration status
func (m *MigrationManager) GetMigrationStatus() ([]Migration, error) {
	// Get applied migrations
	appliedMigrations, err := m.GetAppliedMigrations()
	if err != nil {
		return nil, err
	}

	// Load available migrations
	migrations, err := m.LoadMigrations()
	if err != nil {
		return nil, err
	}

	// Mark applied status
	for i := range migrations {
		migrations[i].Applied = appliedMigrations[migrations[i].Version]
	}

	return migrations, nil
}

// RollbackToVersion rolls back to a specific migration version
func (m *MigrationManager) RollbackToVersion(targetVersion string) error {
	// Note: SQLite doesn't support easy rollbacks, so this is a basic implementation
	// In a production environment, you might want to create explicit rollback migrations
	return fmt.Errorf("rollback functionality not implemented for SQLite - create explicit rollback migrations instead")
}

// CreateMigration creates a new migration file template
func (m *MigrationManager) CreateMigration(description string) (string, error) {
	// Get next version number
	migrations, err := m.LoadMigrations()
	if err != nil {
		return "", err
	}

	nextVersion := "001"
	if len(migrations) > 0 {
		lastMigration := migrations[len(migrations)-1]
		// Parse last version and increment
		if lastVersion := lastMigration.Version; len(lastVersion) == 3 {
			var num int
			if n, _ := fmt.Sscanf(lastVersion, "%03d", &num); n == 1 {
				nextVersion = fmt.Sprintf("%03d", num+1)
			}
		}
	}

	// Create filename
	filename := fmt.Sprintf("%s_%s.sql", nextVersion, strings.ReplaceAll(description, " ", "_"))
	filepath := filepath.Join(m.migrationsDir, filename)

	// Create migration template
	template := fmt.Sprintf(`-- Migration: %s
-- Description: %s
-- Version: %s
-- Date: %s

-- TODO: Add your migration SQL here

-- Insert migration record
INSERT OR IGNORE INTO schema_migrations (version, description, applied_at) 
VALUES ('%s', '%s', CURRENT_TIMESTAMP);`,
		filename, description, nextVersion, "2024-12-19", nextVersion, description)

	// Write file
	if err := ioutil.WriteFile(filepath, []byte(template), 0644); err != nil {
		return "", fmt.Errorf("failed to create migration file: %v", err)
	}

	return filepath, nil
}
