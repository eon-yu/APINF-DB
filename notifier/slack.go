package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"oss-compliance-scanner/models"
	"oss-compliance-scanner/policy"
)

// SlackNotifier handles Slack notifications
type SlackNotifier struct {
	webhookURL string
	username   string
	channel    string
	iconEmoji  string
	maxRetries int
	retryDelay time.Duration
	httpClient *http.Client
}

// NewSlackNotifier creates a new Slack notifier instance
func NewSlackNotifier(webhookURL, username, channel, iconEmoji string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
		username:   username,
		channel:    channel,
		iconEmoji:  iconEmoji,
		maxRetries: 3,
		retryDelay: time.Second * 2,
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}
}

// SlackMessage represents a Slack message structure
type SlackMessage struct {
	Text        string            `json:"text,omitempty"`
	Username    string            `json:"username,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
	Blocks      []SlackBlock      `json:"blocks,omitempty"`
}

// SlackAttachment represents a Slack message attachment
type SlackAttachment struct {
	Color     string       `json:"color,omitempty"`
	Title     string       `json:"title,omitempty"`
	TitleLink string       `json:"title_link,omitempty"`
	Text      string       `json:"text,omitempty"`
	Fields    []SlackField `json:"fields,omitempty"`
	Footer    string       `json:"footer,omitempty"`
	Timestamp int64        `json:"ts,omitempty"`
}

// SlackField represents a field in a Slack attachment
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SlackBlock represents a Slack block element
type SlackBlock struct {
	Type string `json:"type"`
	Text any    `json:"text,omitempty"`
}

// NotificationOptions contains options for notifications
type NotificationOptions struct {
	IncludeDetails     bool
	MaxViolationsShown int
	SeverityThreshold  string
	IncludeSummaryOnly bool
	MentionUsers       []string
	CustomChannel      string
}

// DefaultNotificationOptions returns default notification options
func DefaultNotificationOptions() *NotificationOptions {
	return &NotificationOptions{
		IncludeDetails:     true,
		MaxViolationsShown: 10,
		SeverityThreshold:  "Medium",
		IncludeSummaryOnly: false,
		MentionUsers:       nil,
		CustomChannel:      "",
	}
}

// SendComplianceReport sends a compliance scan report to Slack
func (sn *SlackNotifier) SendComplianceReport(result *policy.EvaluationResult, options *NotificationOptions) error {
	if options == nil {
		options = DefaultNotificationOptions()
	}

	message := sn.buildComplianceMessage(result, options)
	return sn.sendMessage(message)
}

// SendVulnerabilityAlert sends a vulnerability alert to Slack
func (sn *SlackNotifier) SendVulnerabilityAlert(vulnerabilities []*models.Vulnerability, repoName, modulePath string, options *NotificationOptions) error {
	if options == nil {
		options = DefaultNotificationOptions()
	}

	message := sn.buildVulnerabilityMessage(vulnerabilities, repoName, modulePath, options)
	return sn.sendMessage(message)
}

// SendPolicyViolationAlert sends a policy violation alert to Slack
func (sn *SlackNotifier) SendPolicyViolationAlert(violations []*models.PolicyViolation, repoName, modulePath string, options *NotificationOptions) error {
	if options == nil {
		options = DefaultNotificationOptions()
	}

	message := sn.buildViolationMessage(violations, repoName, modulePath, options)
	return sn.sendMessage(message)
}

// SendCustomMessage sends a custom message to Slack
func (sn *SlackNotifier) SendCustomMessage(text string, channel string) error {
	message := &SlackMessage{
		Text:      text,
		Username:  sn.username,
		Channel:   getChannel(channel, sn.channel),
		IconEmoji: sn.iconEmoji,
	}

	return sn.sendMessage(message)
}

// buildComplianceMessage builds a comprehensive compliance report message
func (sn *SlackNotifier) buildComplianceMessage(result *policy.EvaluationResult, options *NotificationOptions) *SlackMessage {
	// Determine message color based on overall status
	color := getStatusColor(result.OverallStatus)
	statusEmoji := getStatusEmoji(result.OverallStatus)

	// Build main text
	mainText := fmt.Sprintf("%s *OSS Compliance Report*", statusEmoji)
	if len(options.MentionUsers) > 0 {
		mentions := make([]string, len(options.MentionUsers))
		for i, user := range options.MentionUsers {
			mentions[i] = fmt.Sprintf("<@%s>", user)
		}
		mainText += fmt.Sprintf(" %s", strings.Join(mentions, " "))
	}

	attachment := SlackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("Repository: %s | Module: %s", result.RepoName, result.ModulePath),
		Footer:    "OSS Compliance Scanner",
		Timestamp: time.Now().Unix(),
	}

	// Add summary fields
	attachment.Fields = append(attachment.Fields,
		SlackField{
			Title: "Overall Status",
			Value: fmt.Sprintf("%s %s", statusEmoji, strings.Title(string(result.OverallStatus))),
			Short: true,
		},
		SlackField{
			Title: "Components Scanned",
			Value: fmt.Sprintf("%d", result.TotalComponents),
			Short: true,
		},
		SlackField{
			Title: "Vulnerabilities Found",
			Value: fmt.Sprintf("%d", result.TotalVulnerabilities),
			Short: true,
		},
		SlackField{
			Title: "Total Violations",
			Value: fmt.Sprintf("%d", result.Summary.TotalViolations),
			Short: true,
		},
	)

	// Add severity breakdown if there are violations
	if result.Summary.TotalViolations > 0 {
		severityBreakdown := fmt.Sprintf(
			"🔴 Critical: %d | 🟠 High: %d | 🟡 Medium: %d | 🟢 Low: %d",
			result.Summary.CriticalViolations,
			result.Summary.HighViolations,
			result.Summary.MediumViolations,
			result.Summary.LowViolations,
		)
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Severity Breakdown",
			Value: severityBreakdown,
			Short: false,
		})

		// Add violation types
		if result.Summary.LicenseViolations > 0 || result.Summary.VulnViolations > 0 {
			violationTypes := fmt.Sprintf(
				"📄 License: %d | 🛡️ Security: %d",
				result.Summary.LicenseViolations,
				result.Summary.VulnViolations,
			)
			attachment.Fields = append(attachment.Fields, SlackField{
				Title: "Violation Types",
				Value: violationTypes,
				Short: false,
			})
		}
	}

	// Add recommendations
	if len(result.Recommendations) > 0 && !options.IncludeSummaryOnly {
		recommendations := strings.Join(result.Recommendations, "\n")
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Recommendations",
			Value: recommendations,
			Short: false,
		})
	}

	// Add detailed violations if requested
	if options.IncludeDetails && !options.IncludeSummaryOnly {
		if len(result.LicenseViolations) > 0 {
			licenseDetails := sn.formatViolations(result.LicenseViolations, options.MaxViolationsShown, "License Violations")
			if licenseDetails != "" {
				attachment.Fields = append(attachment.Fields, SlackField{
					Title: "License Violations",
					Value: licenseDetails,
					Short: false,
				})
			}
		}

		if len(result.VulnViolations) > 0 {
			vulnDetails := sn.formatViolations(result.VulnViolations, options.MaxViolationsShown, "Security Vulnerabilities")
			if vulnDetails != "" {
				attachment.Fields = append(attachment.Fields, SlackField{
					Title: "Security Vulnerabilities",
					Value: vulnDetails,
					Short: false,
				})
			}
		}
	}

	return &SlackMessage{
		Text:        mainText,
		Username:    sn.username,
		Channel:     getChannel(options.CustomChannel, sn.channel),
		IconEmoji:   sn.iconEmoji,
		Attachments: []SlackAttachment{attachment},
	}
}

// buildVulnerabilityMessage builds a vulnerability alert message
func (sn *SlackNotifier) buildVulnerabilityMessage(vulnerabilities []*models.Vulnerability, repoName, modulePath string, options *NotificationOptions) *SlackMessage {
	criticalCount := 0
	highCount := 0
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "Critical":
			criticalCount++
		case "High":
			highCount++
		}
	}

	color := "warning"
	if criticalCount > 0 {
		color = "danger"
	}

	mainText := "🚨 *Vulnerability Alert*"
	if len(options.MentionUsers) > 0 {
		mentions := make([]string, len(options.MentionUsers))
		for i, user := range options.MentionUsers {
			mentions[i] = fmt.Sprintf("<@%s>", user)
		}
		mainText += fmt.Sprintf(" %s", strings.Join(mentions, " "))
	}

	attachment := SlackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("Repository: %s | Module: %s", repoName, modulePath),
		Footer:    "OSS Compliance Scanner",
		Timestamp: time.Now().Unix(),
	}

	attachment.Fields = append(attachment.Fields,
		SlackField{
			Title: "Total Vulnerabilities",
			Value: fmt.Sprintf("%d", len(vulnerabilities)),
			Short: true,
		},
		SlackField{
			Title: "Critical/High",
			Value: fmt.Sprintf("%d/%d", criticalCount, highCount),
			Short: true,
		},
	)

	// Add top vulnerabilities
	if options.IncludeDetails && len(vulnerabilities) > 0 {
		vulnList := sn.formatVulnerabilityList(vulnerabilities, options.MaxViolationsShown)
		if vulnList != "" {
			attachment.Fields = append(attachment.Fields, SlackField{
				Title: "Top Vulnerabilities",
				Value: vulnList,
				Short: false,
			})
		}
	}

	return &SlackMessage{
		Text:        mainText,
		Username:    sn.username,
		Channel:     getChannel(options.CustomChannel, sn.channel),
		IconEmoji:   sn.iconEmoji,
		Attachments: []SlackAttachment{attachment},
	}
}

// buildViolationMessage builds a policy violation message
func (sn *SlackNotifier) buildViolationMessage(violations []*models.PolicyViolation, repoName, modulePath string, options *NotificationOptions) *SlackMessage {
	color := "warning"
	if len(violations) > 0 {
		for _, violation := range violations {
			if violation.Severity == "Critical" {
				color = "danger"
				break
			}
		}
	}

	mainText := "⚠️ *Policy Violation Alert*"
	if len(options.MentionUsers) > 0 {
		mentions := make([]string, len(options.MentionUsers))
		for i, user := range options.MentionUsers {
			mentions[i] = fmt.Sprintf("<@%s>", user)
		}
		mainText += fmt.Sprintf(" %s", strings.Join(mentions, " "))
	}

	attachment := SlackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("Repository: %s | Module: %s", repoName, modulePath),
		Footer:    "OSS Compliance Scanner",
		Timestamp: time.Now().Unix(),
	}

	attachment.Fields = append(attachment.Fields, SlackField{
		Title: "Total Violations",
		Value: fmt.Sprintf("%d", len(violations)),
		Short: true,
	})

	// Add violation details
	if options.IncludeDetails && len(violations) > 0 {
		violationList := sn.formatViolations(violations, options.MaxViolationsShown, "Policy Violations")
		if violationList != "" {
			attachment.Fields = append(attachment.Fields, SlackField{
				Title: "Violations",
				Value: violationList,
				Short: false,
			})
		}
	}

	return &SlackMessage{
		Text:        mainText,
		Username:    sn.username,
		Channel:     getChannel(options.CustomChannel, sn.channel),
		IconEmoji:   sn.iconEmoji,
		Attachments: []SlackAttachment{attachment},
	}
}

// formatViolations formats a list of violations for display
func (sn *SlackNotifier) formatViolations(violations []*models.PolicyViolation, maxShown int, title string) string {
	if len(violations) == 0 {
		return ""
	}

	var lines []string
	count := 0
	for _, violation := range violations {
		if count >= maxShown {
			remaining := len(violations) - count
			lines = append(lines, fmt.Sprintf("... and %d more", remaining))
			break
		}

		emoji := getSeverityEmoji(violation.Severity)
		line := fmt.Sprintf("%s %s", emoji, violation.Description)
		if violation.RecommendedAction != "" {
			line += fmt.Sprintf(" _(Recommendation: %s)_", violation.RecommendedAction)
		}
		lines = append(lines, line)
		count++
	}

	return strings.Join(lines, "\n")
}

// formatVulnerabilityList formats a list of vulnerabilities for display
func (sn *SlackNotifier) formatVulnerabilityList(vulnerabilities []*models.Vulnerability, maxShown int) string {
	if len(vulnerabilities) == 0 {
		return ""
	}

	var lines []string
	count := 0
	for _, vuln := range vulnerabilities {
		if count >= maxShown {
			remaining := len(vulnerabilities) - count
			lines = append(lines, fmt.Sprintf("... and %d more", remaining))
			break
		}

		emoji := getSeverityEmoji(vuln.Severity)
		line := fmt.Sprintf("%s *%s* (%s) - CVSS: %.1f", emoji, vuln.VulnID, vuln.Severity, vuln.CVSS3Score)
		if vuln.Description != "" {
			// Truncate description if too long
			description := vuln.Description
			if len(description) > 100 {
				description = description[:97] + "..."
			}
			line += fmt.Sprintf("\n   %s", description)
		}
		lines = append(lines, line)
		count++
	}

	return strings.Join(lines, "\n")
}

// sendMessage sends a message to Slack with retry logic
func (sn *SlackNotifier) sendMessage(message *SlackMessage) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= sn.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(sn.retryDelay)
		}

		resp, err := sn.httpClient.Post(sn.webhookURL, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			lastErr = fmt.Errorf("failed to send request: %w", err)
			continue
		}

		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}

		lastErr = fmt.Errorf("slack API returned status %d", resp.StatusCode)

		// Don't retry for client errors
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			break
		}
	}

	return fmt.Errorf("failed to send Slack notification after %d attempts: %w", sn.maxRetries+1, lastErr)
}

// ValidateConfiguration validates the Slack notifier configuration
func (sn *SlackNotifier) ValidateConfiguration() error {
	if sn.webhookURL == "" {
		return fmt.Errorf("Slack webhook URL is required")
	}

	if !strings.HasPrefix(sn.webhookURL, "https://hooks.slack.com/") {
		return fmt.Errorf("invalid Slack webhook URL format")
	}

	return nil
}

// TestConnection tests the Slack connection by sending a test message
func (sn *SlackNotifier) TestConnection() error {
	if err := sn.ValidateConfiguration(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	testMessage := &SlackMessage{
		Text:      "🧪 OSS Compliance Scanner test message",
		Username:  sn.username,
		Channel:   sn.channel,
		IconEmoji: sn.iconEmoji,
	}

	return sn.sendMessage(testMessage)
}

// Helper functions

func getStatusColor(status models.PolicyAction) string {
	switch status {
	case models.PolicyActionFail, models.PolicyActionBlock:
		return "danger"
	case models.PolicyActionWarn:
		return "warning"
	case models.PolicyActionAllow:
		return "good"
	default:
		return "#439FE0"
	}
}

func getStatusEmoji(status models.PolicyAction) string {
	switch status {
	case models.PolicyActionFail, models.PolicyActionBlock:
		return "❌"
	case models.PolicyActionWarn:
		return "⚠️"
	case models.PolicyActionAllow:
		return "✅"
	default:
		return "ℹ️"
	}
}

func getSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func getChannel(customChannel, defaultChannel string) string {
	if customChannel != "" {
		return customChannel
	}
	return defaultChannel
}
