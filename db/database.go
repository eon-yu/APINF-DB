package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log"
	"os"
	"oss-compliance-scanner/models"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// go:embed init.sql
var schemaFS embed.FS

// resolveMigrationsPath determines the correct path to migrations directory
func resolveMigrationsPath() string {
	// Check if migrations directory exists in current directory (when running from db package)
	if _, err := os.Stat("migrations"); err == nil {
		return "migrations"
	}

	// Check if db/migrations exists (when running from project root)
	if _, err := os.Stat("db/migrations"); err == nil {
		return "db/migrations"
	}

	// Fallback: try to find it relative to the current file
	if workDir, err := os.Getwd(); err == nil {
		// If we're in the db directory, use relative path
		if filepath.Base(workDir) == "db" {
			return "migrations"
		}
	}

	// Default fallback
	return "db/migrations"
}

// Database represents the database connection and operations
type Database struct {
	conn             *sql.DB
	orm              *gorm.DB
	migrationManager *MigrationManager
}

// NewDatabase creates a new database connection
func NewDatabase(driverName, dataSourceName string) (*Database, error) {
	conn, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	orm, err := gorm.Open(sqlite.Open(dataSourceName), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// 임시로 모델 추가
	err = orm.AutoMigrate(models.SBOM{}, models.Component{}, models.Vulnerability{},
		models.ScanResult{}, models.LicensePolicy{}, models.VulnerabilityPolicy{},
		models.PolicyViolation{}, models.ScanJob{}, models.Report{}, models.Setting{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to auto migrate: %w", err)
	}

	// Configure connection pool
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxLifetime(5 * time.Minute)

	// Initialize migration manager with dynamic path resolution
	migrationsDir := resolveMigrationsPath()
	migrationManager := NewMigrationManager(conn, migrationsDir)

	db := &Database{
		conn:             conn,
		migrationManager: migrationManager,
		orm:              orm,
	}

	// Run migrations instead of initializing schema directly
	if err := db.RunMigrations(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}

// Close closes the database connection
func (db *Database) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

// RunMigrations runs all pending database migrations
func (db *Database) RunMigrations() error {
	log.Println("Running database migrations...")
	return db.migrationManager.Migrate()
}

// GetMigrationStatus returns the current migration status
func (db *Database) GetMigrationStatus() ([]Migration, error) {
	return db.migrationManager.GetMigrationStatus()
}

// InitializeSchema creates the database schema (deprecated - use migrations)
func (db *Database) InitializeSchema() error {
	log.Println("Warning: InitializeSchema is deprecated, please use migrations instead")

	schema, err := schemaFS.ReadFile("init.sql")
	if err != nil {
		return fmt.Errorf("failed to read schema file: %w", err)
	}

	_, err = db.conn.Exec(string(schema))
	if err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	return nil
}

// BeginTransaction starts a new database transaction
func (db *Database) BeginTransaction() (*sql.Tx, error) {
	return db.conn.Begin()
}

// Ping checks database connectivity
func (db *Database) Ping() error {
	return db.conn.Ping()
}

// Query executes a query that returns rows
func (db *Database) Query(query string, args ...any) (*sql.Rows, error) {
	return db.conn.Query(query, args...)
}

// QueryRow executes a query that is expected to return at most one row
func (db *Database) QueryRow(query string, args ...any) *sql.Row {
	return db.conn.QueryRow(query, args...)
}

// Exec executes a query without returning any rows
func (db *Database) Exec(query string, args ...any) (sql.Result, error) {
	return db.conn.Exec(query, args...)
}
