package passwords

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"go4.org/strutil"
	"tmthrgd.dev/go/pwned"
)

// Each line is:
//  prefix, 5-bytes, dataset-only;
//  suffix, 35-bytes;
//  literal ':', 1-byte;
//  count, max 20 bytes;
//  line-endings, max 2-bytes.
// This gives a maximum length of 63-bytes per-line,
// allow some further overhead.
const (
	lineBufSize = 64
	maxLineSize = 96
)

// Reader parses either the raw Pwned Passwords dataset or
// a range query from the ‘Have I been pwned?’ APIv2.
type Reader struct {
	s   *bufio.Scanner
	err error

	count  uint64
	prefix string
	suffix [pwned.SuffixSize]byte

	hexBuf [2 * pwned.SuffixSize]byte

	dataset bool
}

// NewDatasetReader parses the Pwned Passwords list from
// https://haveibeenpwned.com. The provided io.Reader should
// represent pwned-passwords-2.0.txt.
//
// See https://haveibeenpwned.com/Passwords.
func NewDatasetReader(r io.Reader) *Reader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, lineBufSize), maxLineSize)

	return &Reader{
		s: s,

		dataset: true,
	}
}

// NewResultsReader parses the result from a ‘Have I been
// pwned?’ APIv2 range query.
//
// See https://haveibeenpwned.com/API/v2#PwnedPasswords.
func NewResultsReader(r io.Reader, prefix string) *Reader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, lineBufSize), maxLineSize)

	return &Reader{
		s: s,

		prefix: prefix,

		dataset: false,
	}
}

// Scan advances the Reader to the next token, which will
// then be available through the Entry method. It returns
// false when the scan stops, either by reaching the end
// of the input or an error. After Scan returns false, the
// Err method will return any error that occurred during
// scanning, except that if it was io.EOF, Err will return
// nil.
func (r *Reader) Scan() bool {
	if r.err != nil || !r.s.Scan() {
		return false
	}

	line := r.s.Bytes()

	if r.dataset {
		if len(line) < 5 {
			r.err = errors.New("pwned: truncated data")
			return false
		}

		r.prefix, line = string(line[:5]), line[5:]
	}

	const suffixSize = 2*sha1.Size - 5
	if len(line) < suffixSize+1 {
		r.err = errors.New("pwned: truncated data")
		return false
	}

	r.hexBuf[0] = r.prefix[4]
	copy(r.hexBuf[1:], line[:suffixSize])

	if _, r.err = hex.Decode(r.suffix[:], r.hexBuf[:]); r.err != nil {
		return false
	}

	sep, line := line[suffixSize], line[suffixSize+1:]
	if sep != ':' {
		r.err = fmt.Errorf("pwned: invalid data separator %q", sep)
		return false
	}

	r.count, r.err = strutil.ParseUintBytes(line, 10, 64)
	return r.err == nil
}

// Entry returns the most recent entry generated by a call
// to Scan.
func (r *Reader) Entry() (prefix string, suffix [pwned.SuffixSize]byte, count uint64) {
	return r.prefix, r.suffix, r.count
}

// Err returns the first non-EOF error that was encountered
// by the Reader.
func (r *Reader) Err() error {
	if r.err != nil {
		return r.err
	}

	return r.s.Err()
}
