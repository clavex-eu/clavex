package vaultssh

import "testing"

func TestHasCapability(t *testing.T) {
	cases := []struct {
		caps []string
		want string
		ok   bool
	}{
		{[]string{"create", "read"}, "create", true},
		{[]string{"read", "delete"}, "delete", true},
		{[]string{"root"}, "create", true},   // root implies all
		{[]string{"sudo"}, "delete", true},   // sudo implies all
		{[]string{"read"}, "create", false},  // missing
		{[]string{"deny"}, "delete", false},  // explicit deny is not the cap
		{nil, "create", false},               // no caps
	}
	for _, tc := range cases {
		if got := HasCapability(tc.caps, tc.want); got != tc.ok {
			t.Errorf("HasCapability(%v, %q) = %v, want %v", tc.caps, tc.want, got, tc.ok)
		}
	}
}
