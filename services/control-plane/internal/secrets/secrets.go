package secrets

import (
	"errors"
	"regexp"
	"time"
)

const (
	MaximumSecretsPerOwner    = 100
	MaximumGrantsPerWorkspace = 50
	MinimumValueBytes         = 4
	MaximumValueBytes         = 8192
	MaximumGrantedBytes       = 64 * 1024
)

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

type Metadata struct {
	ID           string
	OwnerID      string
	RepositoryID *string
	Name         string
	ValueBytes   int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type WorkspaceGrant struct {
	Secret    Metadata
	Granted   bool
	GrantedAt *time.Time
}

func ValidName(value string) bool { return namePattern.MatchString(value) }

func ValidateValue(value []byte) error {
	if len(value) < MinimumValueBytes || len(value) > MaximumValueBytes {
		return errors.New("secret value must be between 4 and 8192 bytes")
	}
	for _, character := range value {
		if character == 0 {
			return errors.New("secret value contains a null byte")
		}
	}
	return nil
}

func Wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
