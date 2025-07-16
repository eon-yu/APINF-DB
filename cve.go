package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const nvdAPI = "https://services.nvd.nist.gov/rest/json/cve/2.0"

type CVE struct {
	ID               string        `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published        time.Time     `json:"published"`
	LastModified     time.Time     `json:"lastModified"`
	VulnStatus       string        `json:"vulnStatus"`
	CveTags          []string      `json:"cveTags"`
	Descriptions     []Description `json:"descriptions"`
	Metrics          Metrics       `json:"metrics"`
}
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
type Metrics struct {
	CVSSMetricV40 []CVSSMetricV40 `json:"cvssMetricV40"`
}
type CVSSMetricV40 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CvssData CVSSData `json:"cvssData"`
}
type CVSSData struct {
	Version            string  `json:"version"`
	VectorString       string  `json:"vectorString"`
	BaseScore          float64 `json:"baseScore"`
	BaseSeverity       string  `json:"baseSeverity"`
	AttackVector       string  `json:"attackVector"`
	AttackComplexity   string  `json:"attackComplexity"`
	PrivilegesRequired string  `json:"privilegesRequired"`
}
type CVEItem struct {
	CVE CVE `json:"cve"`
}

type NVDResponse struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Format          string    `json:"format"`
	Version         string    `json:"version"`
	Timestamp       time.Time `json:"timestamp"`
	Vulnerabilities []CVEItem `json:"vulnerabilities"`
}

func GetCVSSFromNVD(cveID string) (string, string, error) {

	score := "N/A"
	severity := ""

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(nvdAPI + "?cveId=" + cveID)
	if err != nil {
		return score, severity, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return score, severity, fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return score, severity, fmt.Errorf("failed to read body: %w", err)
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return score, severity, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return score, severity, nil
	}

	secondaryScore := "N/A"
	secondarySeverity := ""
	for _, cvss := range nvdResp.Vulnerabilities[0].CVE.Metrics.CVSSMetricV40 {
		if cvss.Type == "Primary" {
			score = fmt.Sprintf("%.1f", cvss.CvssData.BaseScore)
			severity = cvss.CvssData.BaseSeverity
			break
		} else {
			secondaryScore = fmt.Sprintf("%.1f", cvss.CvssData.BaseScore)
			secondarySeverity = cvss.CvssData.BaseSeverity
		}
	}
	if score == "N/A" {
		score = secondaryScore
		severity = secondarySeverity
	}

	return score, severity, nil
}

// NVD UI → CVSS:3.x 벡터 추출
func ScrapeNvdUI(cveID string) (string, string, error) {
	url := "https://nvd.nist.gov/vuln/detail/" + cveID
	score := "N/A"
	severity := ""
	resp, err := http.Get(url)
	if err != nil {
		return score, severity, fmt.Errorf("NVD UI 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return score, severity, fmt.Errorf("NVD UI 상태 코드: %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return score, severity, fmt.Errorf("goquery 파싱 실패: %w", err)
	}
	doc.Find(".severityDetail").Each(func(i int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if !strings.Contains(text, "N/A") {
			score = strings.Split(text, " ")[0]
			severity = strings.Split(text, " ")[1]
		}
	})

	if score == "N/A" {
		return score, severity, fmt.Errorf("NVD UI에서 CVSS 정보 없음")
	}
	return score, severity, nil
}
