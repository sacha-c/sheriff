package slack

import (
	"log"
	"os"

	"github.com/slack-go/slack"
)

func PostReport(channelName string, text string) (err error) {
	api := slack.New(os.Getenv("SLACK_TOKEN"))

	channels, _, err := api.GetConversations(&slack.GetConversationsParameters{
		ExcludeArchived: true,
		Types:           []string{"private_channel"},
	})
	if err != nil {
		log.Default().Printf("Failed to get slack channel list: %v", err)
		return
	}

	var channelID string
	for _, c := range channels {
		if c.Name == channelName {
			channelID = c.ID
			break
		}
	}
	if channelID == "" {
		log.Default().Printf("Channel %v not found", channelName)
		return
	}

	msgoption := slack.MsgOptionCompose(
		slack.MsgOptionText(text, true),
	)

	_, _, err = api.PostMessage(channelID, msgoption)
	if err != nil {
		log.Default().Printf("Failed to post slack message: %v", err)
		return
	}

	return
}
