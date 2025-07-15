package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Syft로 SBOM 생성
func generateSBOM(filePath, sbomFile string) error {
	cmd := exec.Command("syft", "file:"+filePath, "--output", "cyclonedx-json@1.5="+sbomFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	// cmd = exec.Command("syft", "file:"+filePath, "--output", "json="+filepath.Join(grypeDir, sbomFile), ">", filepath.Join(grypeDir, sbomFile))
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	// return cmd.Run()
	return nil
}

func generateSBOMWithDockerImage(dockerImg, sbomFile string) error {
	cmd := exec.Command("syft", dockerImg, "--output", "cyclonedx-json@1.5="+sbomFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	// cmd = exec.Command("syft", dockerImg, "--output", "json="+filepath.Join(grypeDir, sbomFile), ">", filepath.Join(grypeDir, sbomFile))
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	// return cmd.Run()
	return nil
}

func hasPkgManagerFile(dir string) []string {
	files := []string{
		"go.mod",
		"Cargo.toml",
		"requirements.txt",
		"setup.py",
		"Pipfile",
		"package-lock.json",
		"pom.xml",
		"build.gradle",
		"build.gradle.kts",
		"build.sbt",
		"build.xml",
		"Makefile",
		"meson.build",
		"meson_options.txt",
		"conanfile.txt",
		"conanfile.py",
		"vcpkg.json",
	}
	cFile := "CMakeLists.txt"
	result := []string{}

	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			result = append(result, f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, cFile)); err == nil {
		result = append(result, cFile)
	}
	if len(result) != 0 {
		fmt.Println(dir, ":", result)
	}
	return result
}
