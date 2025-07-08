package cmd

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"oss-compliance-scanner/config"
	"oss-compliance-scanner/db"

	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Database migration management",
	Long:  `Manage database migrations - run, check status, or create new migrations.`,
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Run all pending migrations",
	Long:  `Apply all pending database migrations to bring the schema up to date.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.GetConfig()

		database, err := db.NewDatabase("sqlite3", cfg.Database.Path)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %v", err)
		}
		defer database.Close()

		log.Println("Running database migrations...")
		if err := database.RunMigrations(); err != nil {
			return fmt.Errorf("migration failed: %v", err)
		}

		log.Println("All migrations completed successfully!")
		return nil
	},
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show migration status",
	Long:  `Display the current status of all migrations - which are applied and which are pending.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.GetConfig()

		database, err := db.NewDatabase("sqlite3", cfg.Database.Path)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %v", err)
		}
		defer database.Close()

		migrations, err := database.GetMigrationStatus()
		if err != nil {
			return fmt.Errorf("failed to get migration status: %v", err)
		}

		// Print status table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Version\tDescription\tStatus")
		fmt.Fprintln(w, "-------\t-----------\t------")

		for _, migration := range migrations {
			status := "Pending"
			if migration.Applied {
				status = "Applied"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", migration.Version, migration.Description, status)
		}

		w.Flush()
		return nil
	},
}

var migrateCreateCmd = &cobra.Command{
	Use:   "create [description]",
	Short: "Create a new migration file",
	Long:  `Create a new migration file with the given description.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		description := args[0]

		// Create migration manager (without DB connection for file creation)
		migrationManager := db.NewMigrationManager(nil, "db/migrations")

		filepath, err := migrationManager.CreateMigration(description)
		if err != nil {
			return fmt.Errorf("failed to create migration: %v", err)
		}

		fmt.Printf("Created new migration: %s\n", filepath)
		fmt.Println("Please edit the file to add your migration SQL.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	migrateCmd.AddCommand(migrateCreateCmd)
}
