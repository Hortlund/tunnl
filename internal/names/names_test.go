package names

import "testing"

func TestNormalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
		valid bool
	}{
		{input: " GePh ", want: "geph", valid: true},
		{input: "my-app-2", want: "my-app-2", valid: true},
		{input: "api", valid: false},
		{input: "-broken", valid: false},
		{input: "bad.name", valid: false},
		{input: "ab", valid: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			got, err := Normalize(test.input)
			if (err == nil) != test.valid {
				t.Fatalf("Normalize(%q) error = %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("Normalize(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}
