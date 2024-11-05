package slack

import (
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewService(t *testing.T) {
	s, err := NewService("token", false)

	assert.Nil(t, err)
	assert.NotNil(t, s)
}

func TestPostMessage(t *testing.T) {
	channelID := "1234"
	channelName := "random channel"
	message := slack.MsgOptionText("Hello World", false)

	mockClient := mockClient{}
	mockClient.On("GetConversations", mock.Anything).Return(
		[]slack.Channel{
			{
				GroupConversation: slack.GroupConversation{
					Conversation: slack.Conversation{ID: channelID},
					Name:         channelName,
				},
			},
		},
		"",
		nil,
	)
	mockClient.On("PostMessage", channelID, mock.Anything).Return("", "", nil)

	svc := newService(&mockClient)

	err := svc.PostMessage(channelName, message)

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

type mockClient struct {
	mock.Mock
}

func (c *mockClient) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	args := c.Called(channelID, options)
	return args.String(0), args.String(1), args.Error(2)
}

func (c *mockClient) GetConversations(params *slack.GetConversationsParameters) (channels []slack.Channel, nextCursor string, err error) {
	args := c.Called(params)
	return args.Get(0).([]slack.Channel), args.String(1), args.Error(2)
}
