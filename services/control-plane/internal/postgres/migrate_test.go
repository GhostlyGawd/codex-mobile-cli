package postgres

import (
	"testing"
	"testing/fstest"
)

func TestLoadMigrationsSortsAndChecksums(t *testing.T) {
	filesystem := fstest.MapFS{
		"sql/000002_second.up.sql": {Data: []byte("SELECT 2;\n")},
		"sql/000001_first.up.sql":  {Data: []byte("SELECT 1;\n")},
		"sql/README.md":            {Data: []byte("ignored")},
	}
	items, err := loadMigrations(filesystem, "sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].version != 1 || items[1].version != 2 {
		t.Fatalf("unexpected migration order: %#v", items)
	}
	if items[0].checksum == items[1].checksum {
		t.Fatal("different migrations received the same checksum")
	}
}

func TestLoadMigrationsRejectsInvalidOrDuplicateVersion(t *testing.T) {
	tests := []struct {
		name       string
		filesystem fstest.MapFS
	}{
		{
			name: "invalid name",
			filesystem: fstest.MapFS{
				"bad.up.sql": {Data: []byte("SELECT 1")},
			},
		},
		{
			name: "duplicate version",
			filesystem: fstest.MapFS{
				"000001_one.up.sql": {Data: []byte("SELECT 1")},
				"000001_two.up.sql": {Data: []byte("SELECT 2")},
			},
		},
		{
			name: "empty migration",
			filesystem: fstest.MapFS{
				"000001_empty.up.sql": {Data: []byte(" \n")},
			},
		},
		{
			name: "down migration",
			filesystem: fstest.MapFS{
				"000001_rollback.down.sql": {Data: []byte("SELECT 1")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := loadMigrations(test.filesystem, "."); err == nil {
				t.Fatal("expected migration validation error")
			}
		})
	}
}
