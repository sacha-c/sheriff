package slack

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/slack-go/slack"
)

type Service struct {
	client *slack.Client
}

func New(token string) *Service {
	return &Service{
		client: slack.New(token),
	}
}

func (s *Service) PostReport(channelName string, text string) (err error) {
	channels, _, err := s.client.GetConversations(&slack.GetConversationsParameters{
		ExcludeArchived: true,
		Types:           []string{"private_channel"},
	})
	if err != nil {
		return errors.Join(errors.New("failed to get slack channel list"), err)
	}

	var channelID string
	for _, c := range channels {
		if c.Name == channelName {
			channelID = c.ID
			break
		}
	}
	if channelID == "" {
		return fmt.Errorf("channel %v not found", channelName)
	}

	if _, err := s.client.UploadFileV2(slack.UploadFileV2Parameters{
		Channel:  channelID,
		Filename: fmt.Sprintf("Security_Report_%v.md", time.Now().Format("2006-01-02")),
		FileSize: utf8.RuneCountInString(text),
		Content:  text,
	}); err != nil {
		return errors.Join(errors.New("failed to post slack message"))
	}

	return
}
