package terminal

import (
	"bytes"
	"strings"
	"sync"
	"unicode/utf8"
)

const maxOSCBytes = 64 << 10

// OutputFilter removes remote clipboard writes and bounds OSC sequences. It is
// stateful because a hostile control sequence may be split across PTY reads.
type OutputFilter struct {
	mu      sync.Mutex
	pending []byte
}

func (f *OutputFilter) Process(input []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, input...)
	output := make([]byte, 0, len(f.pending))
	for {
		start := bytes.Index(f.pending, []byte{0x1b, ']'})
		if start < 0 {
			if len(f.pending) > 0 && f.pending[len(f.pending)-1] == 0x1b {
				output = append(output, f.pending[:len(f.pending)-1]...)
				f.pending = append([]byte(nil), f.pending[len(f.pending)-1:]...)
			} else {
				output = append(output, f.pending...)
				f.pending = f.pending[:0]
			}
			break
		}
		output = append(output, f.pending[:start]...)
		end, terminator := oscEnd(f.pending[start+2:])
		if end < 0 {
			if len(f.pending)-start > maxOSCBytes {
				// Drop the pathological prefix and continue scanning future bytes.
				f.pending = append([]byte(nil), f.pending[start+maxOSCBytes:]...)
				continue
			}
			f.pending = append([]byte(nil), f.pending[start:]...)
			break
		}
		content := f.pending[start+2 : start+2+end]
		if safe := safeOSC(content); safe != nil {
			output = append(output, 0x1b, ']')
			output = append(output, safe...)
			output = append(output, f.pending[start+2+end:start+2+end+terminator]...)
		}
		f.pending = append([]byte(nil), f.pending[start+2+end+terminator:]...)
	}
	return output
}

func (f *OutputFilter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.pending {
		f.pending[i] = 0
	}
	f.pending = nil
}

func oscEnd(input []byte) (int, int) {
	for i := range input {
		if input[i] == 0x07 {
			return i, 1
		}
		if input[i] == 0x1b && i+1 < len(input) && input[i+1] == '\\' {
			return i, 2
		}
	}
	return -1, 0
}

func safeOSC(content []byte) []byte {
	command, payload, found := bytes.Cut(content, []byte{';'})
	if !found {
		return nil
	}
	switch string(command) {
	case "52":
		return nil
	case "0", "2":
		payload = sanitizeText(payload, 256)
		return append(append(append([]byte(nil), command...), ';'), payload...)
	case "8":
		if len(payload) > 4096 || bytes.IndexByte(payload, 0) >= 0 {
			return nil
		}
		return append(append(append([]byte(nil), command...), ';'), payload...)
	default:
		if len(content) > 16<<10 {
			return nil
		}
		return append([]byte(nil), content...)
	}
}

func sanitizeText(input []byte, limit int) []byte {
	text := strings.ToValidUTF8(string(input), "")
	output := make([]rune, 0, len(text))
	for _, r := range text {
		if r >= 0x20 && r != 0x7f {
			output = append(output, r)
		}
		if len(string(output)) >= limit {
			break
		}
	}
	result := []byte(string(output))
	for len(result) > limit || !utf8.Valid(result) {
		result = result[:len(result)-1]
	}
	return result
}
