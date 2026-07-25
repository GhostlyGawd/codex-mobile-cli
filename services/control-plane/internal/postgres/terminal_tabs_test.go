package postgres

import "testing"

func TestValidTerminalTabOrder(t *testing.T) {
	t.Parallel()
	if !validTerminalTabOrder([]string{"tab-a", "tab-b"}) {
		t.Fatal("valid exact terminal order was rejected")
	}
	for _, value := range [][]string{
		nil,
		{},
		{""},
		{"tab-a", "tab-a"},
		makeTerminalTabIDs(65),
	} {
		if validTerminalTabOrder(value) {
			t.Fatalf("invalid terminal order was accepted: %#v", value)
		}
	}
}

func makeTerminalTabIDs(count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = string(rune('a' + index))
	}
	return values
}
