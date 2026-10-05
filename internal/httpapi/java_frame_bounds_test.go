package httpapi

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/mshilts/incarnate-web-gateway/internal/config"
)

func TestReadJavaLineAcceptsExactLimitAcrossFragments(t *testing.T) {
	frame := bytes.Repeat([]byte("x"), 64)
	reader := bufio.NewReaderSize(bytes.NewReader(append(frame, '\n')), 16)
	got, err := readJavaLine(reader, int64(len(frame)))
	if err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("exact-limit fragmented frame: bytes=%d err=%v", len(got), err)
	}
}

func TestReadJavaLineRejectsAboveServerLimit(t *testing.T) {
	frame := strings.Repeat("x", int(config.DefaultMaxJavaFrameBytes)+1) + "\n"
	reader := bufio.NewReaderSize(strings.NewReader(frame), 1024)
	got, err := readJavaLine(reader, config.DefaultMaxJavaFrameBytes)
	if err == nil || err.Error() != "java frame too large" || got != nil {
		t.Fatalf("oversized server frame: bytes=%d err=%v", len(got), err)
	}
}
