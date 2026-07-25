package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"sync"
)

const (
	Replacement = "[REDACTED]"

	minimumSecretBytes  = 4
	maximumSecrets      = 50
	maximumSecretBytes  = 64 << 10
	maximumPatterns     = 1024
	maximumPatternBytes = 32 << 10
	maximumDerivedBytes = 2 << 20
)

var ErrUnsafeSecrets = errors.New("redaction secrets are outside the supported bounds")

type Redactor struct {
	patterns [][]byte
}

// New derives exact values and the common encodings produced by command-line
// tools. Values shorter than four bytes fail closed because replacing them in
// arbitrary terminal text would make the terminal unusable while allowing
// them through would make the redaction guarantee untrue.
func New(secrets ...[]byte) (*Redactor, error) {
	patterns, err := derivePatterns(secrets)
	if err != nil {
		return nil, err
	}
	return &Redactor{patterns: patterns}, nil
}

func (r *Redactor) String(input string) string {
	return string(r.Bytes([]byte(input)))
}

func (r *Redactor) Bytes(input []byte) []byte {
	if r == nil || len(r.patterns) == 0 || len(input) == 0 {
		return bytes.Clone(input)
	}
	output := bytes.Clone(input)
	for _, pattern := range r.patterns {
		if !bytes.Contains(output, pattern) {
			continue
		}
		replaced := bytes.ReplaceAll(output, pattern, []byte(Replacement))
		clear(output)
		output = replaced
	}
	return output
}

// Close makes a best-effort wipe of the derived patterns retained in memory.
// Callers must separately wipe the authoritative plaintext buffers supplied to
// New, because the redactor never takes ownership of them.
func (r *Redactor) Close() {
	if r == nil {
		return
	}
	for _, pattern := range r.patterns {
		clear(pattern)
	}
	r.patterns = nil
}

// Stream redacts a byte stream without exposing matches split across PTY read
// boundaries. It retains only a suffix that is still a possible pattern
// prefix; ordinary bytes are emitted immediately, preserving live terminal
// behavior without a maximum-secret-length delay.
type Stream struct {
	mu       sync.Mutex
	root     *trieNode
	state    *trieNode
	patterns [][]byte
	pending  []byte
	closed   bool
}

type trieNode struct {
	children map[byte]*trieNode
	fail     *trieNode
	depth    int
	ownMatch int
	match    int
}

func NewStream(secrets ...[]byte) (*Stream, error) {
	patterns, err := derivePatterns(secrets)
	if err != nil {
		return nil, err
	}
	root := &trieNode{children: make(map[byte]*trieNode)}
	for _, pattern := range patterns {
		node := root
		for _, value := range pattern {
			if node.children[value] == nil {
				node.children[value] = &trieNode{children: make(map[byte]*trieNode), depth: node.depth + 1}
			}
			node = node.children[value]
		}
		node.ownMatch = len(pattern)
		node.match = len(pattern)
	}
	buildFailureLinks(root)
	return &Stream{root: root, state: root, patterns: patterns}, nil
}

func (s *Stream) Process(input []byte) []byte {
	if s == nil {
		return []byte(Replacement)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return []byte(Replacement)
	}
	return s.processLocked(input)
}

// Flush releases a final non-matching prefix when the authoritative PTY
// closes. Complete matches are still redacted. Calling Flush does not disable
// future Process calls; Close owns that lifecycle transition.
func (s *Stream) Flush() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	output := make([]byte, 0, len(s.pending))
	if s.state.ownMatch > 0 {
		output = append(output, s.pending[:len(s.pending)-s.state.ownMatch]...)
		output = append(output, Replacement...)
	} else {
		output = append(output, s.pending...)
	}
	clear(s.pending)
	s.pending = nil
	s.state = s.root
	return output
}

func (s *Stream) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	clear(s.pending)
	s.pending = nil
	for _, pattern := range s.patterns {
		clear(pattern)
	}
	s.patterns = nil
	clearTrie(s.root)
	s.root = nil
	s.state = nil
	s.closed = true
}

func (s *Stream) processLocked(input []byte) []byte {
	output := make([]byte, 0, len(input))
	for _, value := range input {
		// A complete form can also be the prefix of a longer form (notably
		// padded and unpadded base64). Hold it for one more transition and,
		// when the longer form does not continue, redact before processing the
		// new byte from the root.
		if s.state.ownMatch > 0 && len(s.state.children) > 0 && s.state.children[value] == nil {
			safe := len(s.pending) - s.state.ownMatch
			output = append(output, s.pending[:safe]...)
			output = append(output, Replacement...)
			clear(s.pending)
			s.pending = nil
			s.state = s.root
		}
		s.pending = append(s.pending, value)
		for s.state != s.root && s.state.children[value] == nil {
			s.state = s.state.fail
		}
		if next := s.state.children[value]; next != nil {
			s.state = next
		} else {
			s.state = s.root
		}

		if s.state.match > 0 && !(s.state.ownMatch == s.state.match && len(s.state.children) > 0) {
			safe := len(s.pending) - s.state.match
			output = append(output, s.pending[:safe]...)
			output = append(output, Replacement...)
			clear(s.pending)
			s.pending = nil
			s.state = s.root
			continue
		}

		safe := len(s.pending) - s.state.depth
		if safe > 0 {
			output = append(output, s.pending[:safe]...)
			copy(s.pending, s.pending[safe:])
			clear(s.pending[s.state.depth:])
			s.pending = s.pending[:s.state.depth]
		}
	}
	return output
}

func buildFailureLinks(root *trieNode) {
	root.fail = root
	queue := make([]*trieNode, 0, len(root.children))
	for _, child := range root.children {
		child.fail = root
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for value, child := range node.children {
			failure := node.fail
			for failure != root && failure.children[value] == nil {
				failure = failure.fail
			}
			if candidate := failure.children[value]; candidate != nil {
				child.fail = candidate
			} else {
				child.fail = root
			}
			if child.fail.match > child.match {
				child.match = child.fail.match
			}
			queue = append(queue, child)
		}
	}
}

func derivePatterns(secrets [][]byte) ([][]byte, error) {
	if len(secrets) > maximumSecrets {
		return nil, ErrUnsafeSecrets
	}
	patterns := make([][]byte, 0, len(secrets)*12)
	buckets := make(map[[32]byte][]int)
	totalSecretBytes, totalPatternBytes := 0, 0
	add := func(pattern []byte) error {
		defer clear(pattern)
		if len(pattern) < minimumSecretBytes {
			return ErrUnsafeSecrets
		}
		if len(pattern) > maximumPatternBytes || len(patterns) >= maximumPatterns || totalPatternBytes+len(pattern) > maximumDerivedBytes {
			return ErrUnsafeSecrets
		}
		hash := sha256.Sum256(pattern)
		for _, index := range buckets[hash] {
			if bytes.Equal(patterns[index], pattern) {
				return nil
			}
		}
		patterns = append(patterns, bytes.Clone(pattern))
		buckets[hash] = append(buckets[hash], len(patterns)-1)
		totalPatternBytes += len(pattern)
		return nil
	}
	fail := func() ([][]byte, error) {
		for _, pattern := range patterns {
			clear(pattern)
		}
		return nil, ErrUnsafeSecrets
	}
	for _, secret := range secrets {
		if len(secret) < minimumSecretBytes || len(secret) > 8192 || bytes.IndexByte(secret, 0) >= 0 {
			return fail()
		}
		totalSecretBytes += len(secret)
		if totalSecretBytes > maximumSecretBytes {
			return fail()
		}
		forms := encodedForms(secret)
		for index, form := range forms {
			if err := add(form); err != nil {
				for _, remaining := range forms[index+1:] {
					clear(remaining)
				}
				return fail()
			}
		}
	}
	sort.Slice(patterns, func(i, j int) bool {
		if len(patterns[i]) == len(patterns[j]) {
			return bytes.Compare(patterns[i], patterns[j]) < 0
		}
		return len(patterns[i]) > len(patterns[j])
	})
	return patterns, nil
}

func encodedForms(value []byte) [][]byte {
	forms := make([][]byte, 0, 16)
	forms = append(forms, bytes.Clone(value))
	lowerHex := make([]byte, hex.EncodedLen(len(value)))
	hex.Encode(lowerHex, value)
	forms = append(forms, lowerHex, bytes.ToUpper(lowerHex))
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := make([]byte, encoding.EncodedLen(len(value)))
		encoding.Encode(encoded, value)
		forms = append(forms, encoded)
		if encoding == base64.StdEncoding {
			for _, width := range []int{64, 76} {
				forms = append(forms, wrap(encoded, width, []byte{'\n'}), wrap(encoded, width, []byte{'\r', '\n'}))
			}
		}
	}
	queryEncoded := []byte(url.QueryEscape(string(value)))
	pathEncoded := []byte(url.PathEscape(string(value)))
	forms = append(forms, queryEncoded, lowerPercentHex(queryEncoded), pathEncoded, lowerPercentHex(pathEncoded))
	return forms
}

func wrap(value []byte, width int, separator []byte) []byte {
	if width <= 0 || len(value) <= width {
		return bytes.Clone(value)
	}
	lines := (len(value) - 1) / width
	result := make([]byte, 0, len(value)+lines*len(separator))
	for offset := 0; offset < len(value); offset += width {
		if offset != 0 {
			result = append(result, separator...)
		}
		result = append(result, value[offset:min(offset+width, len(value))]...)
	}
	return result
}

func lowerPercentHex(value []byte) []byte {
	result := bytes.Clone(value)
	for index := 0; index+2 < len(result); index++ {
		if result[index] != '%' {
			continue
		}
		for offset := 1; offset <= 2; offset++ {
			if result[index+offset] >= 'A' && result[index+offset] <= 'F' {
				result[index+offset] += 'a' - 'A'
			}
		}
		index += 2
	}
	return result
}

func clearTrie(node *trieNode) {
	if node == nil {
		return
	}
	for value, child := range node.children {
		clearTrie(child)
		delete(node.children, value)
	}
	node.fail = nil
	node.depth = 0
	node.ownMatch = 0
	node.match = 0
}
