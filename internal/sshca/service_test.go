package sshca

import "testing"

func TestBaseMount(t *testing.T) {
	cases := map[string]string{
		"ssh":                      "ssh",
		"ssh-rot-abc12345":         "ssh",
		"ssh-prod":                 "ssh-prod",
		"ssh-prod-rot-deadbeef":    "ssh-prod",
		"pam-ssh-rot-1-rot-2":      "pam-ssh", // strips at first -rot-, stays bounded
	}
	for in, want := range cases {
		if got := baseMount(in); got != want {
			t.Errorf("baseMount(%q) = %q, want %q", in, got, want)
		}
	}
}
