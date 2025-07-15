package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Match struct {
	Vulnerabilities []struct {
		ID          string      `json:"id"`
		Description string      `json:"description"`
		References  []Reference `json:"references"`
		Ratings     []Rating    `json:"ratings"`
	} `json:"vulnerabilities"`
}
type Reference struct {
	ID     string `json:"id"`
	Source Source `json:"source"`
}
type Source struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}
type Rating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Method   string  `json:"method"`
	Vector   string  `json:"vector"`
}
type GrypeResult struct {
	Description string      `json:"description"`
	References  []Reference `json:"references"`
	Ratings     []Rating    `json:"ratings"`
	Seen        bool        `json:"seen"`
}

const grypeDir = "./grype"

func runGrype(sbomFile string) error {

	grypeFile := filepath.Join(grypeDir, sbomFile)
	err := generateGrype(sbomFile)
	if err != nil {
		return err
	}

	currentCVE, err := loadCVEList(grypeFile)
	if err != nil {
		panic("현재 결과 파일 읽기 실패: " + err.Error())
	}
	defer os.Rename(grypeFile, grypeFile+"_previous.json")

	var previousCVE map[string]GrypeResult
	firstRun := false
	if _, err := os.Stat(grypeFile + "_previous.json"); err == nil {
		previousCVE, _ = loadCVEList(grypeFile + "_previous.json")
	} else {
		firstRun = true
	}
	var newCVEs map[string]GrypeResult
	if firstRun {
		newCVEs = currentCVE
	} else {
		newCVEs = diffCVEList(currentCVE, previousCVE)
	}
	if err := sendSlackWebhook(newCVEs, projectName+"-"+strings.ReplaceAll(sbomFile, sbomFileName, "")); err != nil {
		fmt.Println("❌ 슬랙 전송 실패:", err)
	}
	return nil
}

func generateGrype(sbomFile string) error {
	cmd := exec.Command("grype", sbomFile, "-o", "cyclonedx-json="+filepath.Join(grypeDir, sbomFile))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadCVEList(filePath string) (map[string]GrypeResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var raw Match
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	grypeResult := make(map[string]GrypeResult)
	for _, vulnerability := range raw.Vulnerabilities {
		cve := vulnerability.ID
		grypeResult[cve] = GrypeResult{
			Description: vulnerability.Description,
			References:  vulnerability.References,
			Ratings:     vulnerability.Ratings,
			Seen:        true,
		}

	}
	return grypeResult, nil
}

func diffCVEList(current, previous map[string]GrypeResult) map[string]GrypeResult {
	prevMap := make(map[string]GrypeResult)
	for cve, result := range previous {
		prevMap[cve] = result
	}

	diff := make(map[string]GrypeResult)
	for cve, result := range current {
		if !prevMap[cve].Seen {
			diff[cve] = result
		}
	}
	return diff
}

func mkGrypeDir() error {
	if _, err := os.Stat(grypeDir); os.IsNotExist(err) {
		return os.MkdirAll(grypeDir, 0755)
	}
	return nil
}
