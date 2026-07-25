package hostdisk

import "testing"

func TestFreeGiBRejectsEmptyPath(t *testing.T) {
	t.Parallel()
	if _, err := FreeGiB(""); err == nil {
		t.Fatal("expected an empty path to be rejected")
	}
}

func TestFreeGiBCurrentFilesystem(t *testing.T) {
	t.Parallel()
	free, err := FreeGiB(".")
	if err != nil {
		t.Fatal(err)
	}
	if free < 0 {
		t.Fatalf("negative free space: %d", free)
	}
}
