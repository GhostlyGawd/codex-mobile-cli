package secrets

import "testing"

func TestNamesAndValuesAreBounded(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"TOKEN", "_PRIVATE", "A1_B2"} {
		if !ValidName(value) {
			t.Fatalf("valid environment name rejected: %q", value)
		}
	}
	for _, value := range []string{"", "1TOKEN", "BAD-NAME", "A.B", "A=B"} {
		if ValidName(value) {
			t.Fatalf("invalid environment name accepted: %q", value)
		}
	}
	if ValidateValue(nil) == nil || ValidateValue([]byte("abc")) == nil || ValidateValue(make([]byte, MaximumValueBytes+1)) == nil || ValidateValue([]byte{'a', 0, 'b', 'c'}) == nil {
		t.Fatal("invalid secret value accepted")
	}
	value := []byte("secret")
	if err := ValidateValue(value); err != nil {
		t.Fatal(err)
	}
	Wipe(value)
	for _, character := range value {
		if character != 0 {
			t.Fatal("secret buffer was not wiped")
		}
	}
}
