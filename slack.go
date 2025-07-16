package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func sendSlackWebhook(cves map[string]GrypeResult, service string) error {

	if len(cves) == 0 {
		fmt.Printf("✅ [%s] 신규 취약점 없음\n", service)
		return nil
	}
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf(":rotating_light: *[%s]* 신규 취약점 [%d개] 발견!\n", service, len(cves)))
	for cve, result := range cves {
		if msg.Len() > 30000 {
			sendSlackWebhookAPI(msg)
			msg.Reset()
		}
		id := cve
		desc := result.Description
		score := "N/A"
		severity := ""
		var err error
		if len(result.Ratings) > 0 {
			score = fmt.Sprintf("%.1f", result.Ratings[0].Score)
			severity = result.Ratings[0].Severity
		}
		if score == "0.0" && strings.HasPrefix(id, "CVE-") {
			score, severity, err = GetCVSSFromNVD(id)
			if err != nil {
				score, severity, err = ScrapeNvdUI(id)
			}
			if err != nil {
				fmt.Println("❌ 취약점 점수 조회 실패:", err)
			}
		}
		sourceURL := "https://github.com/advisories/" + id
		if result.References[0].Source.URL != "" {
			sourceURL = result.References[0].Source.URL
		}
		msg.WriteString(fmt.Sprintf("• *<%s|%s>*  —  *Score:* %s (%s)\n", sourceURL, id, score, severity))
		if len(desc) > 255 {
			desc = strings.Split(desc, "\n")[0]
		}
		msg.WriteString(fmt.Sprintf("  ➤ _%s_\n\n", desc))
		cveCount++
	}
	sendSlackWebhookAPI(msg)
	return nil
}

func sendSlackWebhookAPI(msg strings.Builder) error {
	payload := fmt.Sprintf(`{"text": %q}`, msg.String())
	req, err := http.NewRequest("POST", slackWebhookURL, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("[Slack 응답]", string(body))
	return nil
}
