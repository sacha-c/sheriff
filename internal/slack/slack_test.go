package slack

import "testing"

func TestCanCreateService(t *testing.T) {
	s := New("token", false)

	if s.client == nil {
		t.Error("Expected client to be set")
	}
}
