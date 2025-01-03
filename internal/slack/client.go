// Package slack provides a Slack service to interact with the Slack API.
package slack

// This client is a thin wrapper around the slack-go library. It provides an interface to the Slack client
// The main purpose of this client is to provide an interface to the GitLab client which can be mocked in tests.
// As such this MUST be as thin as possible and MUST not contain any business logic, since it is not testable.

import "github.com/slack-go/slack"

type iclient interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
	GetConversations(params *slack.GetConversationsParameters) (channels []slack.Channel, nextCursor string, err error)
}

type client struct {
	client *slack.Client
}

func (c *client) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	return c.client.PostMessage(channelID, options...)
}

func (c *client) GetConversations(params *slack.GetConversationsParameters) (channels []slack.Channel, nextCursor string, err error) {
	return c.client.GetConversations(params)
}
