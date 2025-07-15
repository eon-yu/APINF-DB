package main

import (
	"os"
	"os/exec"
)

func generateSBOMWithCycloneDX(filePath, sbomFile string) error {
	cmd := exec.Command("npx", "@cyclonedx/cdxgen", "-t", filePath, "-o", sbomFile, "--output-format", "json", "--spec-version", "1.5")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
