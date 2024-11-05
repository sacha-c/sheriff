package slack

import (
	"errors"
	"fmt"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

type Service struct {
	client IClient
}

func newService(c IClient) Service {
	return Service{
		client: c,
	}
}

func NewService(token string, debug bool) (*Service, error) {
	slackClient := slack.New(token, slack.OptionDebug(debug))
	if slackClient == nil {
		return nil, errors.New("failed to create slack client")
	}

	s := newService(&Client{client: slackClient})

	return &s, nil
}

func (s *Service) PostMessage(channelName string, options ...slack.MsgOption) (err error) {
	channel, err := s.findSlackChannel(channelName)
	if err != nil {
		return
	}

	if _, _, err := s.client.PostMessage(channel.ID, options...); err != nil {
		return errors.Join(errors.New("failed to post slack message"), err)
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
			Limit:           1000,
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

		log.Debug().Msgf("Channel %v not found in current page, fetching next page %v", channelName, nextCursor)
	}
}
