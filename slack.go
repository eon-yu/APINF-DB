package main

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func sendSlackWebhook(cves map[string]GrypeResult, service string) error {

	if len(cves) == 0 {
		fmt.Printf("✅ [%s] 신규 취약점 없음\n", service)
		return nil
	}
	msgText := []struct {
		Name        string
		Score       float64
		Severity    string
		Description string
		URL         string
	}{}

	for cve, result := range cves {
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
				fmt.Printf("❌ 취약점 점수 조회 실패(%s):%s\n", id, err)
			}
		}
		sourceURL := "https://github.com/advisories/" + id
		if result.References[0].Source.URL != "" {
			sourceURL = result.References[0].Source.URL
		}
		fScore, err := strconv.ParseFloat(score, 64)
		if err != nil {
			fScore = -1.0
		}
		if len(desc) > 255 {
			desc = strings.Split(desc, "\n")[0]
		}
		msgText = append(msgText, struct {
			Name        string
			Score       float64
			Severity    string
			Description string
			URL         string
		}{
			Name:        id,
			Score:       fScore,
			Severity:    severity,
			Description: desc,
			URL:         sourceURL,
		})
	}

	sort.Slice(msgText, func(i, j int) bool {
		return msgText[i].Score > msgText[j].Score
	})

	var msg strings.Builder
	msg.WriteString(fmt.Sprintf(":rotating_light: *[%s]* 신규 취약점 [%d개] 발견!\n", service, len(cves)))
	for _, text := range msgText {
		if msg.Len() > 30000 {
			sendSlackWebhookAPI(msg)
			msg.Reset()
		}
		score := fmt.Sprintf("%.1f", text.Score)
		if text.Score < 0.0 {
			score = "N/A"
		}
		msg.WriteString(fmt.Sprintf("• *<%s|%s>*  —  *Score:* %s (%s)\n", text.URL, text.Name, score, strings.ToUpper(text.Severity)))
		if len(text.Description) > 0 {
			msg.WriteString(fmt.Sprintf("  ➤ _%s_\n\n", text.Description))
		}
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
