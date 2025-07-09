package main

import (
	"fmt"
	"log"
	"os"

	"oss-compliance-scanner/cmd"
	"oss-compliance-scanner/config"
	"oss-compliance-scanner/logging"
)

var (
	version = "1.0.0"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Set up logging
	cfg := config.GetConfig()
	if err := logging.Init(cfg.Logging); err != nil {
		// Fallback to default stderr logging if initialization fails
		log.Printf("Logging initialization failed: %v", err)
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// Execute the root command
	if err := cmd.Execute(version, commit, date); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
