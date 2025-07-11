package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

const fileName = "-bom.json"

var apiKey string = ""
var parentName string
var parentVersion string
var rootDir string = "/Users/stclab/Desktop/IQ-square"

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("환경 변수 파일 로드 실패: %v", err)
	}
	apiKey = os.Getenv("API_KEY")
	if apiKey == "" {
		panic("API_KEY 환경 변수가 설정되지 않았습니다.")
	}

	rootDirPtr := flag.String("root", rootDir, "멀티 모듈 루트 디렉토리")
	parentNamePtr := flag.String("parent", "", "부모 모듈 이름")
	parentVersionPtr := flag.String("parent-version", "latest", "부모 모듈 버전")
	flag.Parse()

	if *parentNamePtr == "" {
		panic("부모 모듈 이름이 필요합니다.")
	}

	parentName = *parentNamePtr
	parentVersion = *parentVersionPtr
	rootDir = *rootDirPtr

	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != rootDir {
			for _, f := range hasPkgManagerFile(path) {
				err := runTask(path, info.Name(), f)
				if err != nil {
					log.Printf("❌ [%s] 작업 실패: %v\n", info.Name(), err)
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("파일 탐색 실패: %v", err)
	}
}

func runTask(path string, moduleName string, libName string) error {
	var err error
	sbomFile := fmt.Sprintf("./%s-%s%s", moduleName, libName, fileName)
	projectName := fmt.Sprintf("%s(%s)", moduleName, libName)
	fmt.Printf("🔍 [%s] Syft 스캔 시작\n", moduleName)
	if strings.Contains(libName, "Dockerfile") {
		projectName = fmt.Sprintf("%s(%s)", moduleName, "Dockerfile")
		err = generateSBOMWithCycloneDX(filepath.Join(path, libName), sbomFile)
	} else if libName == "CMakeLists.txt" {
		err = generateSBOMWithCycloneDX(filepath.Join(path, libName), sbomFile)
	} else {
		err = generateSBOM(filepath.Join(path, libName), sbomFile)
	}
	defer os.Remove(sbomFile)
	if err != nil {
		log.Printf("❌ [%s] Syft 스캔 실패: %v\n", projectName, err)
		return err
	}

	fmt.Printf("📝 [%s] SBOM에 projectName 패치\n", projectName)
	err = patchSBOMProjectName(sbomFile, projectName)
	if err != nil {
		log.Printf("❌ [%s] SBOM 패치 실패: %v\n", projectName, err)
		return err
	}

	fmt.Printf("🚀 [%s] Dependency-Track 업로드 시작\n", projectName)
	err = uploadSBOM(sbomFile, projectName)
	if err != nil {
		log.Printf("❌ [%s] Dependency-Track 업로드 실패: %v\n", projectName, err)
	} else {
		fmt.Printf("✅ [%s] 업로드 완료\n", projectName)
	}

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
	dockerFile := "Dockerfile"
	result := []string{}

	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			result = append(result, f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, cFile)); err == nil {
		result = append(result, cFile)
	}
	entries, _ := os.ReadDir(dir)

	for _, entry := range entries {
		if strings.Contains(entry.Name(), dockerFile) {
			result = append(result, entry.Name())
		}
	}
	if len(result) != 0 {
		fmt.Println(dir, ":", result)
	}
	return result
}
