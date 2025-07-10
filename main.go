package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	dtrackURL = "http://localhost:8081/api/v1/bom"              // Dependency-Track 서버 URL
	apiKey    = "odt_lv6eNy2e_IBFMXCa6zN2YW9IdwkEuGbAwuqS4XjSw" // API Key
	rootDir   = "/Users/stclab/Desktop/IQ-square"               // 멀티 모듈 루트 디렉토리
)

func main() {
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && path != rootDir && hasPkgManagerFile(path) {
			moduleName := info.Name()
			sbomFile := fmt.Sprintf("./%s-bom.json", moduleName)
			// os.Create(sbomFile)

			fmt.Printf("🔍 [%s] Syft 스캔 시작\n", moduleName)
			err := generateSBOM(path, sbomFile)
			if err != nil {
				log.Printf("❌ [%s] Syft 스캔 실패: %v\n", moduleName, err)
				return nil
			}

			fmt.Printf("📝 [%s] SBOM에 projectName 패치\n", moduleName)
			err = patchSBOMProjectName(sbomFile, moduleName)
			if err != nil {
				log.Printf("❌ [%s] SBOM 패치 실패: %v\n", moduleName, err)
				return nil
			}

			fmt.Printf("🚀 [%s] Dependency-Track 업로드 시작\n", moduleName)
			err = uploadSBOM(sbomFile, moduleName)
			if err != nil {
				log.Printf("❌ [%s] Dependency-Track 업로드 실패: %v\n", moduleName, err)
			} else {
				fmt.Printf("✅ [%s] 업로드 완료\n", moduleName)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("파일 탐색 실패: %v", err)
	}
}
func hasPkgManagerFile(dir string) bool {
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
		"CMakeLists.txt",
		"Makefile",
		"meson.build",
		"meson_options.txt",
		"conanfile.txt",
		"conanfile.py",
		"vcpkg.json",
		"Dockerfile",
	}

	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			fmt.Println(filepath.Join(dir, f))
			return true
		}
	}
	return false
}
