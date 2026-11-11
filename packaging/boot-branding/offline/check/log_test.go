package main

import (
	"bytes"
	"errors"
	"io"
	"syscall"
	"testing"
)

type countedReader struct {
	*bytes.Reader
	consumed int
	eof      bool
}

func (r *countedReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	r.consumed += n
	r.eof = err == io.EOF
	return n, err
}

type brokenWriter struct{ short bool }

func (w brokenWriter) Write(data []byte) (int, error) {
	if w.short {
		return len(data) / 2, nil
	}
	return 0, syscall.ENOSPC
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestBoundedLogExactBoundaryAndFooter(t *testing.T) {
	for _, size := range []int{0, logLimit - 1, logLimit, logLimit + 1, logLimit * 2} {
		input := bytes.Repeat([]byte{'A'}, size)
		reader := &countedReader{Reader: bytes.NewReader(input)}
		var output bytes.Buffer
		err := boundedLog(&output, reader, logLimit)
		if reader.consumed != size || !reader.eof {
			t.Fatal("input was not drained to EOF")
		}
		if output.Len() > logLimit {
			t.Fatal("log exceeded cap")
		}
		if size <= logLimit {
			if err != nil || !bytes.Equal(output.Bytes(), input) {
				t.Fatalf("untruncated input changed at %d: %v", size, err)
			}
		} else if err == nil || !bytes.HasSuffix(output.Bytes(), []byte(truncatedLog)) || bytes.Count(output.Bytes(), []byte(truncatedLog)) != 1 {
			t.Fatal("overflow lacks exactly one footer and failure")
		}
	}
}

func TestBoundedLogDrainsAfterDiskAndPartialWriteFailures(t *testing.T) {
	for _, short := range []bool{false, true} {
		input := bytes.Repeat([]byte{'A'}, logLimit+1)
		reader := &countedReader{Reader: bytes.NewReader(input)}
		err := boundedLog(brokenWriter{short: short}, reader, logLimit)
		want := error(syscall.ENOSPC)
		if short {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) || reader.consumed != len(input) || !reader.eof {
			t.Fatalf("write error interrupted drain: %v/%d", err, reader.consumed)
		}
	}
}

func TestBoundedLogReportsReadFailure(t *testing.T) {
	if err := boundedLog(io.Discard, brokenReader{}, logLimit); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}
