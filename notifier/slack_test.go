package notifier

import (
	"testing"

	"oss-compliance-scanner/models"
	"oss-compliance-scanner/policy"
)

func TestNewSlackNotifier(t *testing.T) {
	notifier := NewSlackNotifier(
		"https://hooks.slack.com/test",
		"OSS Scanner",
		"#security",
		":shield:",
	)

	if notifier == nil {
		t.Error("NewSlackNotifier should return a valid notifier")
	}

	if notifier.webhookURL != "https://hooks.slack.com/test" {
		t.Errorf("Expected webhookURL 'https://hooks.slack.com/test', got %s", notifier.webhookURL)
	}

	if notifier.username != "OSS Scanner" {
		t.Errorf("Expected username 'OSS Scanner', got %s", notifier.username)
	}

	if notifier.channel != "#security" {
		t.Errorf("Expected channel '#security', got %s", notifier.channel)
	}

	if notifier.iconEmoji != ":shield:" {
		t.Errorf("Expected iconEmoji ':shield:', got %s", notifier.iconEmoji)
	}

	if notifier.maxRetries != 3 {
		t.Errorf("Expected maxRetries 3, got %d", notifier.maxRetries)
	}
}

func TestDefaultNotificationOptions(t *testing.T) {
	options := DefaultNotificationOptions()

	if options == nil {
		t.Fatal("DefaultNotificationOptions should return valid options")
	}

	if !options.IncludeDetails {
		t.Error("Expected IncludeDetails to be true")
	}

	if options.MaxViolationsShown != 10 {
		t.Errorf("Expected MaxViolationsShown 10, got %d", options.MaxViolationsShown)
	}

	if options.SeverityThreshold != "Medium" {
		t.Errorf("Expected SeverityThreshold 'Medium', got %s", options.SeverityThreshold)
	}

	if options.IncludeSummaryOnly {
		t.Error("Expected IncludeSummaryOnly to be false")
	}
}

func TestSlackNotifier_ValidateConfiguration_Valid(t *testing.T) {
	notifier := NewSlackNotifier(
		"https://hooks.slack.com/test",
		"OSS Scanner",
		"#security",
		":shield:",
	)

	err := notifier.ValidateConfiguration()
	if err != nil {
		t.Errorf("ValidateConfiguration should pass for valid config, got: %v", err)
	}
}

func TestSlackNotifier_ValidateConfiguration_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		webhookURL string
		username   string
		channel    string
		iconEmoji  string
		wantError  bool
	}{
		{
			name:       "empty webhook URL",
			webhookURL: "",
			username:   "OSS Scanner",
			channel:    "#security",
			iconEmoji:  ":shield:",
			wantError:  true,
		},
		{
			name:       "invalid webhook URL",
			webhookURL: "not-a-url",
			username:   "OSS Scanner",
			channel:    "#security",
			iconEmoji:  ":shield:",
			wantError:  true,
		},
		{
			name:       "empty username",
			webhookURL: "https://hooks.slack.com/test",
			username:   "",
			channel:    "#security",
			iconEmoji:  ":shield:",
			wantError:  false, // Username is optional
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notifier := NewSlackNotifier(tt.webhookURL, tt.username, tt.channel, tt.iconEmoji)
			err := notifier.ValidateConfiguration()

			if tt.wantError && err == nil {
				t.Error("Expected validation error")
			}

			if !tt.wantError && err != nil {
				t.Errorf("Expected no validation error, got: %v", err)
			}
		})
	}
}

func TestSlackNotifier_BuildComplianceMessage(t *testing.T) {
	notifier := NewSlackNotifier(
		"https://hooks.slack.com/test",
		"OSS Scanner",
		"#security",
		":shield:",
	)

	result := &policy.EvaluationResult{
		RepoName:             "test-repo",
		ModulePath:           "backend",
		TotalComponents:      25,
		TotalVulnerabilities: 5,
		OverallStatus:        models.PolicyActionBlock,
		Summary: policy.ViolationSummary{
			TotalViolations:    7,
			CriticalViolations: 1,
			HighViolations:     2,
			MediumViolations:   3,
			LowViolations:      1,
		},
	}

	options := DefaultNotificationOptions()
	message := notifier.buildComplianceMessage(result, options)

	if message == nil {
		t.Fatal("buildComplianceMessage should return a message")
	}

	if message.Username != "OSS Scanner" {
		t.Errorf("Expected username 'OSS Scanner', got %s", message.Username)
	}

	if message.Channel != "#security" {
		t.Errorf("Expected channel '#security', got %s", message.Channel)
	}

	if message.IconEmoji != ":shield:" {
		t.Errorf("Expected iconEmoji ':shield:', got %s", message.IconEmoji)
	}

	if len(message.Attachments) == 0 {
		t.Error("Expected at least one attachment")
	}

	attachment := message.Attachments[0]
	if attachment.Color == "" {
		t.Error("Expected attachment color to be set")
	}

	if len(attachment.Fields) == 0 {
		t.Error("Expected attachment fields to be set")
	}
}

func TestSlackNotifier_SendCustomMessage(t *testing.T) {
	notifier := NewSlackNotifier(
		"https://hooks.slack.com/invalid", // Will fail to send, but we're testing message construction
		"OSS Scanner",
		"#security",
		":shield:",
	)

	err := notifier.SendCustomMessage("Test message", "#test-channel")
	// We expect this to fail due to invalid webhook, but it should not panic
	if err == nil {
		t.Log("SendCustomMessage succeeded (webhook must be valid)")
	} else {
		t.Logf("SendCustomMessage failed as expected: %v", err)
	}
}

func TestSlackNotifier_SendPolicyViolationAlert(t *testing.T) {
	notifier := NewSlackNotifier(
		"https://hooks.slack.com/invalid",
		"OSS Scanner",
		"#security",
		":shield:",
	)

	violations := []*models.PolicyViolation{
		{
			ViolationType:     models.ViolationTypeLicense,
			Severity:          "High",
			Description:       "GPL-3.0 license not allowed",
			RecommendedAction: "Replace with MIT license",
		},
		{
			ViolationType:     models.ViolationTypeVulnerability,
			Severity:          "Critical",
			Description:       "Critical vulnerability found",
			RecommendedAction: "Update package immediately",
		},
	}

	options := DefaultNotificationOptions()
	err := notifier.SendPolicyViolationAlert(violations, "test-repo", "backend", options)

	// We expect this to fail due to invalid webhook
	if err == nil {
		t.Log("SendPolicyViolationAlert succeeded (webhook must be valid)")
	} else {
		t.Logf("SendPolicyViolationAlert failed as expected: %v", err)
	}
}

func TestSlackNotifier_SendVulnerabilityAlert(t *testing.T) {
	notifier := NewSlackNotifier(
		"https://hooks.slack.com/invalid",
		"OSS Scanner",
		"#security",
		":shield:",
	)

	vulnerabilities := []*models.Vulnerability{
		{
			VulnID:      "CVE-2021-1234",
			Severity:    "Critical",
			Description: "Critical vulnerability in package",
		},
		{
			VulnID:      "CVE-2021-5678",
			Severity:    "High",
			Description: "High severity vulnerability",
		},
	}

	options := DefaultNotificationOptions()
	err := notifier.SendVulnerabilityAlert(vulnerabilities, "test-repo", "frontend", options)

	// We expect this to fail due to invalid webhook
	if err == nil {
		t.Log("SendVulnerabilityAlert succeeded (webhook must be valid)")
	} else {
		t.Logf("SendVulnerabilityAlert failed as expected: %v", err)
	}
}

func TestGetStatusColor(t *testing.T) {
	tests := []struct {
		status   models.PolicyAction
		expected string
	}{
		{models.PolicyActionBlock, "danger"},
		{models.PolicyActionFail, "danger"},
		{models.PolicyActionWarn, "warning"},
		{models.PolicyActionAllow, "good"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := getStatusColor(tt.status)
			if result != tt.expected {
				t.Errorf("Expected color '%s' for status '%s', got '%s'", tt.expected, tt.status, result)
			}
		})
	}
}

func TestGetStatusEmoji(t *testing.T) {
	tests := []struct {
		status   models.PolicyAction
		hasEmoji bool
	}{
		{models.PolicyActionBlock, true},
		{models.PolicyActionFail, true},
		{models.PolicyActionWarn, true},
		{models.PolicyActionAllow, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			result := getStatusEmoji(tt.status)
			if tt.hasEmoji && result == "" {
				t.Errorf("Expected emoji for status '%s', got empty string", tt.status)
			}
		})
	}
}

func TestGetSeverityEmoji(t *testing.T) {
	tests := []struct {
		severity string
		hasEmoji bool
	}{
		{"Critical", true},
		{"High", true},
		{"Medium", true},
		{"Low", true},
		{"Unknown", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := getSeverityEmoji(tt.severity)
			if tt.hasEmoji && result == "" {
				t.Errorf("Expected emoji for severity '%s', got empty string", tt.severity)
			}
		})
	}
}

func TestGetChannel(t *testing.T) {
	tests := []struct {
		name           string
		customChannel  string
		defaultChannel string
		expected       string
	}{
		{
			name:           "use custom channel",
			customChannel:  "#custom",
			defaultChannel: "#default",
			expected:       "#custom",
		},
		{
			name:           "use default channel",
			customChannel:  "",
			defaultChannel: "#default",
			expected:       "#default",
		},
		{
			name:           "empty custom channel",
			customChannel:  " ",
			defaultChannel: "#default",
			expected:       " ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getChannel(tt.customChannel, tt.defaultChannel)
			if result != tt.expected {
				t.Errorf("Expected channel '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestNotificationOptions_CustomValues(t *testing.T) {
	options := &NotificationOptions{
		IncludeDetails:     false,
		MaxViolationsShown: 5,
		SeverityThreshold:  "High",
		IncludeSummaryOnly: true,
		MentionUsers:       []string{"@security-team"},
		CustomChannel:      "#critical-alerts",
	}

	if options.IncludeDetails {
		t.Error("Expected IncludeDetails to be false")
	}

	if options.MaxViolationsShown != 5 {
		t.Errorf("Expected MaxViolationsShown 5, got %d", options.MaxViolationsShown)
	}

	if options.SeverityThreshold != "High" {
		t.Errorf("Expected SeverityThreshold 'High', got %s", options.SeverityThreshold)
	}

	if !options.IncludeSummaryOnly {
		t.Error("Expected IncludeSummaryOnly to be true")
	}

	if len(options.MentionUsers) != 1 {
		t.Errorf("Expected 1 mention user, got %d", len(options.MentionUsers))
	}

	if options.CustomChannel != "#critical-alerts" {
		t.Errorf("Expected CustomChannel '#critical-alerts', got %s", options.CustomChannel)
	}
}
