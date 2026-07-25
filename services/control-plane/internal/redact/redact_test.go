package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestRedactsExactAndEncodedFormsLongestFirst(t *testing.T) {
	secret := []byte("p@ss word/token:123456")
	r, err := New(secret, []byte("word/token"))
	if err != nil {
		t.Fatal(err)
	}
	forms := []string{
		string(secret),
		base64.StdEncoding.EncodeToString(secret),
		base64.RawURLEncoding.EncodeToString(secret),
		"p%40ss+word%2Ftoken%3A123456",
	}
	output := r.String("prefix " + strings.Join(forms, " / ") + " suffix")
	for _, form := range forms {
		if strings.Contains(output, form) {
			t.Fatalf("secret form remained: %q in %q", form, output)
		}
	}
	if strings.Count(output, Replacement) != len(forms) {
		t.Fatalf("expected one marker per form, got %q", output)
	}
}

func TestRejectsDangerouslyShortSecretAndCopiesBytes(t *testing.T) {
	if _, err := New([]byte("abc")); err == nil {
		t.Fatal("expected short secret rejection")
	}
	r, _ := New([]byte("secret-value"))
	input := []byte("safe")
	output := r.Bytes(input)
	output[0] = 'S'
	if input[0] != 's' {
		t.Fatal("Bytes must return an independent buffer")
	}
}

func TestStreamRedactsEverySplitOfExactAndEncodedSecrets(t *testing.T) {
	secret := []byte("granted-value/with spaces:123456")
	forms := []string{
		string(secret),
		base64.StdEncoding.EncodeToString(secret),
		"granted-value%2Fwith+spaces%3A123456",
	}
	for _, form := range forms {
		for split := 0; split <= len(form); split++ {
			stream, err := NewStream(secret)
			if err != nil {
				t.Fatal(err)
			}
			output := append(stream.Process([]byte("before "+form[:split])), stream.Process([]byte(form[split:]+" after"))...)
			output = append(output, stream.Flush()...)
			stream.Close()
			if strings.Contains(string(output), form) || string(output) != "before "+Replacement+" after" {
				t.Fatalf("split %d left form %q in %q", split, form, output)
			}
		}
	}
}

func TestStreamPreservesFidelityWithoutMaximumPatternDelay(t *testing.T) {
	stream, err := NewStream([]byte("very-long-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if output := string(stream.Process([]byte("ordinary terminal output"))); output != "ordinary terminal output" {
		t.Fatalf("ordinary output was delayed or changed: %q", output)
	}
	if output := string(stream.Process([]byte("very-"))); output != "" {
		t.Fatalf("possible secret prefix escaped before the next chunk: %q", output)
	}
	if output := string(stream.Process([]byte("safe"))); output != "very-safe" {
		t.Fatalf("non-matching prefix did not recover faithfully: %q", output)
	}
}

func TestStreamFlushAndClosedStateFailClosed(t *testing.T) {
	stream, err := NewStream([]byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if output := stream.Process([]byte("secret-")); len(output) != 0 {
		t.Fatalf("partial secret prefix escaped: %q", output)
	}
	if output := string(stream.Flush()); output != "secret-" {
		t.Fatalf("EOF prefix was not faithfully flushed: %q", output)
	}
	stream.Close()
	if output := string(stream.Process([]byte("untrusted"))); output != Replacement {
		t.Fatalf("closed redactor did not fail closed: %q", output)
	}
}
