package postgres

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAdvisoryLockKeyIsPostgresTextSafe(t *testing.T) {
	key := advisoryLockKey("device-instance\x00namespace", "owner\x00id", string([]byte{0xff, 0x00, 0x01}))
	if strings.ContainsRune(key, '\x00') {
		t.Fatalf("advisory key contains NUL: %q", key)
	}
	if !utf8.ValidString(key) {
		t.Fatalf("advisory key is not valid UTF-8: %q", key)
	}
	if key != "v1;25:6465766963652d696e7374616e6365006e616d657370616365;8:6f776e6572006964;3:ff0001;" {
		t.Fatalf("advisory key framing changed: %q", key)
	}
}

func TestAdvisoryLockKeyFramesNamespaceAndTupleBoundaries(t *testing.T) {
	keys := []string{
		advisoryLockKey("terminal-tab-order", "a", "bc"),
		advisoryLockKey("terminal-tab-order", "ab", "c"),
		advisoryLockKey("terminal-tab-order", "a:1", "bc"),
		advisoryLockKey("device-instance", "a", "bc"),
	}
	for index, left := range keys {
		for otherIndex, right := range keys {
			if index != otherIndex && left == right {
				t.Fatalf("distinct advisory tuples %d and %d aliased to %q", index, otherIndex, left)
			}
		}
	}
}
