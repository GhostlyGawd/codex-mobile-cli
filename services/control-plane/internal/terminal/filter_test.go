package terminal

import (
	"bytes"
	"testing"
)

func TestOutputFilterDropsSplitOSC52AndSanitizesTitle(t *testing.T) {
	f := &OutputFilter{}
	first := f.Process([]byte("before\x1b]52;c;c2Vj"))
	if string(first) != "before" {
		t.Fatalf("unexpected first output %q", first)
	}
	second := f.Process([]byte("cmV0\x07after\x1b]2;safe\x00 title\x1b\\"))
	if bytes.Contains(second, []byte("c2VjcmV0")) || bytes.Contains(second, []byte{0}) {
		t.Fatalf("clipboard/title content was not sanitized: %q", second)
	}
	want := []byte("after\x1b]2;safe title\x1b\\")
	if !bytes.Equal(second, want) {
		t.Fatalf("got %q want %q", second, want)
	}
}

func TestOutputFilterPreservesNormalTerminalBytesAndIncompleteEscape(t *testing.T) {
	f := &OutputFilter{}
	if got := f.Process([]byte("abc\x1b")); string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := f.Process([]byte("[31mred")); string(got) != "\x1b[31mred" {
		t.Fatalf("got %q", got)
	}
}
