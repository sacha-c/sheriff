package slack

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
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
	channel, err := s.findSlackChannel(channelName)
	if err != nil {
		return
	}

	if _, err := s.client.UploadFileV2(slack.UploadFileV2Parameters{
		Channel:  channel.ID,
		Filename: fmt.Sprintf("Security_Report_%v.md", time.Now().Format("2006-01-02")),
		FileSize: utf8.RuneCountInString(text),
		Content:  text,
	}); err != nil {
		return errors.Join(errors.New("failed to post slack message"))
	}

	log.Info().Msgf("Posted slack message to channel %v", channelName)

	return
}

func (s *Service) findSlackChannel(channelName string) (channel *slack.Channel, err error) {
	var nextCursor string
	var channels []slack.Channel

	for {
		if channels, nextCursor, err = s.client.GetConversations(&slack.GetConversationsParameters{
			ExcludeArchived: true,
			Cursor:          nextCursor,
			Types:           []string{"public_channel", "private_channel"},
		}); err != nil {
			return nil, errors.Join(errors.New("failed to get slack channel list"), err)
		}

		idx := pie.FindFirstUsing(channels, func(c slack.Channel) bool { return c.Name == channelName })
		if idx > -1 {
			log.Info().Msgf("Found slack channel %v", channelName)
			channel = &channels[idx]
			return
		} else if nextCursor == "" {
			return nil, fmt.Errorf("channel %v not found", channelName)
		}
	}
}
