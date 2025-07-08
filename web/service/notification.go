package service

import (
	"fmt"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/notifier"
	"time"

	"github.com/gofiber/fiber/v2"
)

type NotificationService struct {
	database *db.Database
}

func NewNotificationService(db *db.Database) *NotificationService {
	return &NotificationService{database: db}
}

// Slack test request structure
type SlackTestRequest struct {
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
}

// handleAPISlackTest sends a test Slack notification
func (ds *NotificationService) HandleAPISlackTest(c *fiber.Ctx) error {
	var req SlackTestRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	if req.WebhookURL == "" {
		return c.Status(400).JSON(fiber.Map{"error": "webhook_url is required"})
	}

	// Create Slack notifier with test configuration
	slackNotifier := notifier.NewSlackNotifier(
		req.WebhookURL,
		"OSS Compliance Scanner",
		req.Channel,
		":shield:",
	)

	// Validate configuration first
	if err := slackNotifier.ValidateConfiguration(); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   "Invalid Slack configuration",
			"details": err.Error(),
		})
	}

	// Send a custom test message
	testMessage := fmt.Sprintf(`🧪 *OSS Compliance Scanner - 알림 테스트*

✅ Slack 알림 기능이 정상적으로 작동하고 있습니다.

*시스템 정보:* OSS Compliance Scanner v1.0.0
*테스트 시간:* %s
*참고사항:* 이 메시지는 관리자 페이지에서 발송된 테스트 알림입니다.`,
		time.Now().Format("2006-01-02 15:04:05"))

	if err := slackNotifier.SendCustomMessage(testMessage, req.Channel); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to send Slack test notification",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Slack 테스트 알림이 성공적으로 전송되었습니다.",
	})
}

// sendSlackMessage is a helper function to send Slack messages
func (ds *NotificationService) SendSlackMessage(slackNotifier *notifier.SlackNotifier, message *notifier.SlackMessage) error {
	// Use the notifier's SendCustomMessage method for simple text
	if len(message.Attachments) == 0 {
		return slackNotifier.SendCustomMessage(message.Text, message.Channel)
	}

	// For messages with attachments, convert to text format
	messageText := message.Text
	if len(message.Attachments) > 0 {
		attachment := message.Attachments[0]
		if len(attachment.Fields) > 0 {
			messageText += "\n\n"
			for _, field := range attachment.Fields {
				messageText += fmt.Sprintf("*%s:* %s\n", field.Title, field.Value)
			}
		}
	}

	return slackNotifier.SendCustomMessage(messageText, message.Channel)
}
