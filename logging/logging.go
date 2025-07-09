package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"oss-compliance-scanner/config"
)

// Init sets up the global logger according to configuration.
// It supports writing to stdout/stderr plus optional file output.
// Multiple outputs are combined via io.MultiWriter.
func Init(cfg config.LoggingConfig) error {
	var writers []io.Writer

	switch cfg.Output {
	case "", "stdout":
		writers = append(writers, os.Stdout)
	case "stderr":
		writers = append(writers, os.Stderr)
	case "file":
		// no console writer when file only
	default:
		// treat as custom path
		writers = append(writers, os.Stdout)
	}

	// Determine log file path if configured or if Output=="file"
	logFilePath := cfg.File
	if logFilePath == "" {
		// default path under ./logs/app-YYYYMMDD.log
		logFilePath = filepath.Join("logs", fmt.Sprintf("app-%s.log", time.Now().Format("20060102")))
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(logFilePath), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	writers = append(writers, file)

	mw := io.MultiWriter(writers...)
	log.SetOutput(mw)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	return nil
}
