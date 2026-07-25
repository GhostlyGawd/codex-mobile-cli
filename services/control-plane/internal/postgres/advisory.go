package postgres

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// advisoryLockKey frames every namespace/component by its original byte
// length and hex-encodes the bytes. The result is unambiguous across component
// boundaries and always valid PostgreSQL text, even for hostile input that
// contains NUL or invalid UTF-8.
func advisoryLockKey(namespace string, components ...string) string {
	var key strings.Builder
	key.WriteString("v1;")
	writeAdvisoryLockKeyComponent(&key, namespace)
	for _, component := range components {
		writeAdvisoryLockKeyComponent(&key, component)
	}
	return key.String()
}

func writeAdvisoryLockKeyComponent(key *strings.Builder, value string) {
	key.WriteString(strconv.Itoa(len(value)))
	key.WriteByte(':')
	key.WriteString(hex.EncodeToString([]byte(value)))
	key.WriteByte(';')
}
