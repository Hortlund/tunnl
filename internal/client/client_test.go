package client

import "testing"

func TestJoinURLPath(t *testing.T) {
	t.Parallel()
	tests := []struct{ base, request, want string }{
		{"", "/users", "/users"},
		{"/api", "/users", "/api/users"},
		{"/api/", "/users/", "/api/users/"},
	}
	for _, test := range tests {
		if got := joinURLPath(test.base, test.request); got != test.want {
			t.Errorf("joinURLPath(%q, %q) = %q, want %q", test.base, test.request, got, test.want)
		}
	}
}
