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

const sbomFileName = "-bom.json"

var dtrackURL string = ""
var apiKey string = ""
var parentName string
var parentVersion string
var rootDir string = ""
var slackWebhookURL string = ""

func runTask(path string, moduleName string, libName string) error {
	var err error
	sbomFile := fmt.Sprintf("./%s-%s%s", moduleName, libName, sbomFileName)
	projectName := fmt.Sprintf("%s(%s)", moduleName, libName)
	fmt.Printf("🔍 [%s] Syft 스캔 시작\n", moduleName)
	switch libName {
	case "CMakeLists.txt":
		err = generateSBOMWithCycloneDX(filepath.Join(path, libName), sbomFile)
	case "":
		err = generateSBOMWithDockerImage(moduleName, sbomFile)
	default:
		err = generateSBOM(filepath.Join(path, libName), sbomFile)
	}
	if err != nil {
		log.Printf("❌ [%s] Syft 스캔 실패: %v\n", projectName, err)
		return err
	}
	if err = runGrype(sbomFile, projectName); err != nil {
		log.Printf("❌ [%s] Grype 실패: %v\n", projectName, err)
		return err
	}
	defer os.Remove(sbomFile)

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

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("환경 변수 파일 로드 실패: %v", err)
	}
	slackWebhookURL = os.Getenv("SLACK_WEBHOOK_URL")
	if slackWebhookURL == "" {
		panic("SLACK_WEBHOOK_URL 환경 변수가 설정되지 않았습니다.")
	}
	serverHost := os.Getenv("DP_TRACK_SERVER_HOST")
	if serverHost == "" {
		panic("SERVER_HOST 환경 변수가 설정되지 않았습니다.")
	}
	dtrackURL = "http://" + serverHost + ":8081/api/v1/bom"

	apiKey = os.Getenv("DP_TRACK_API_KEY")
	if apiKey == "" {
		panic("API_KEY 환경 변수가 설정되지 않았습니다.")
	}
	fmt.Println(dtrackURL)
	fmt.Println(apiKey)

	rootDirPtr := flag.String("root", rootDir, "멀티 모듈 루트 디렉토리")
	parentNamePtr := flag.String("parent", "", "부모 모듈 이름")
	parentVersionPtr := flag.String("parent-version", "latest", "부모 모듈 버전")
	dockerImg := flag.String("docker-image", "", "Docker Image 이름")
	flag.Parse()

	if *parentNamePtr == "" {
		panic("부모 모듈 이름이 필요합니다.")
	}

	parentName = *parentNamePtr
	parentVersion = *parentVersionPtr
	rootDir = *rootDirPtr
	if *dockerImg != "" {
		if len(strings.Split(*dockerImg, ":")) == 2 {
			runTask(rootDir, *dockerImg, "")
		} else {
			panic("Docker Image 이름이 올바르지 않습니다.")
		}
	}
	if *dockerImg == "" && *rootDirPtr == "" {
		panic("멀티/단일 모듈 루트 디렉토리 또는 Docker Image 이름이 필요합니다.")
	}
	if *rootDirPtr == "" {
		return
	}

	err = mkGrypeDir()
	if err != nil {
		panic(err)
	}
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
