package slack

import (
	"errors"
	"fmt"

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

	msgoption := slack.MsgOptionCompose(
		slack.MsgOptionText(text, true),
	)

	_, _, err = s.client.PostMessage(channelID, msgoption)
	if err != nil {
		return errors.Join(errors.New("failed to post slack message"))
	}

	return
}
