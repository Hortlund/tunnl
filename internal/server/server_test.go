package server

import "testing"

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()
	if !constantTimeEqual("correct horse", "correct horse") {
		t.Fatal("equal tokens were rejected")
	}
	if constantTimeEqual("correct horse", "wrong horse") {
		t.Fatal("different tokens were accepted")
	}
}
