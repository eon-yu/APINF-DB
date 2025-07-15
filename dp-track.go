package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// SBOM에 projectName 주입
func patchSBOMProjectName(sbomFile, projectName string) error {
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		return err
	}

	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	// Grafana v.11 처리
	if component, ok := obj["components"].([]any); ok {
		for _, c := range component {
			if c, ok := c.(map[string]any); ok {
				if name, ok := c["name"].(string); ok {
					if strings.Contains(name, "github.com/grafana/grafana") {
						c["version"] = "v11.0.0"
						c["purl"] = c["purl"].(string) + "@v11.0.0"
						c["cpe"] = "cpe:2.3:a:grafana:grafana:v11.0.0:*:*:*:*:*:*:*"
					}
				}
			}
		}
	}

	if metadata, ok := obj["metadata"].(map[string]any); ok {
		if component, ok := metadata["component"].(map[string]any); ok {
			component["name"] = projectName
			metadata["component"] = component
		} else {
			metadata["component"] = map[string]any{"name": projectName, "type": "application"}
		}
		obj["metadata"] = metadata
	} else {
		obj["metadata"] = map[string]any{
			"component": map[string]any{
				"name": projectName,
				"type": "library",
			},
		}
	}

	updated, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sbomFile, updated, 0644)
}

// Dependency-Track에 SBOM 업로드
func uploadSBOM(sbomFile, moduleName string) error {
	if strings.HasSuffix(moduleName, "()") {
		moduleName = strings.TrimSuffix(moduleName, "()")
		moduleName = moduleName + "(dockerImage)"
	} else if !strings.Contains(sbomFile, "CMakeLists.txt") {
		cmd := exec.Command("cyclonedx",
			"convert", "--input-file", sbomFile, "--output-file", sbomFile,
			"--output-format", "json", "--output-version", "v1_5")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			return err
		}
	}
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		panic(err)
	}
	// 2. base64 인코딩
	encoded := base64.StdEncoding.EncodeToString(data)

	// 3. 요청 JSON 생성
	reqBody := map[string]any{
		"projectName":    moduleName,
		"projectVersion": "latest",
		"parentName":     parentName,
		"parentVersion":  parentVersion,
		"autoCreate":     true,
		"bom":            encoded,
	}
	jsonData, _ := json.Marshal(reqBody)

	// 4. HTTP POST 호출
	req, _ := http.NewRequest("PUT", dtrackURL, bytes.NewBuffer(jsonData))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("업로드 실패: %s - %s", resp.Status, string(body))
	}

	return nil
}
