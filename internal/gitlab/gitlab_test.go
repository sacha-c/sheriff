package gitlab

import (
	"testing"
)

func TestCanCreateService(t *testing.T) {
	s, err := NewService("token")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if s.client == nil {
		t.Error("Expected client to be set")
	}
}
