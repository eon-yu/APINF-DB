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
	msg.WriteString(fmt.Sprintf(":rotating_light: *[%s]* 신규 취약점 발견!\n", service))
	for cve, result := range cves {
		id := cve
		desc := result.Description
		score := "N/A"
		if len(result.Ratings) > 0 {
			score = fmt.Sprintf("%.2f", result.Ratings[0].Score)
		}
		sourceURL := "https://github.com/advisories/" + id
		if result.References[0].Source.URL != "" {
			sourceURL = result.References[0].Source.URL
		}
		msg.WriteString(fmt.Sprintf("• *<%s|%s>*  —  *Score:* %s\n", sourceURL, id, score))
		msg.WriteString(fmt.Sprintf("  ➤ _%s_\n\n", desc))
	}

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
