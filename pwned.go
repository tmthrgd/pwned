// Package pwned provides a password checking client and server
// accessible via gRPC.
package pwned

import (
	"crypto/sha1"
	"encoding/hex"
	"math/bits"
)

//go:generate protoc ./pwned.proto --go_out=plugins=grpc:internal/proto

const (
	// PrefixSize is the expected length of the prefix
	// in hexadecimal characters.
	PrefixSize = 5

	// SuffixSize is the expected length of the suffix
	// in bytes.
	SuffixSize = sha1.Size - PrefixSize/2
)

// Size returns the byte size required to store N results.
func Size(N int) int {
	return N * (SuffixSize + 1)
}

// SplitDigest breaks the sha1 digest into a prefix, which
// is sent to the server, and a suffix, which is compared
// locally.
func SplitDigest(digest [sha1.Size]byte) (prefix string, suffix [SuffixSize]byte) {
	prefix = hex.EncodeToString(digest[:(PrefixSize+1)/2])[:PrefixSize]
	copy(suffix[:], digest[PrefixSize/2:])
	return prefix, suffix
}

// AppendResult adds a suffix and it's count to the
// provided buffer. It should be called sequentially until
// all results have been added.
func AppendResult(buf []byte, suffix [SuffixSize]byte, count uint64) []byte {
	buf = append(buf, suffix[:]...)

	n := 63 - bits.LeadingZeros64(count)
	return append(buf, byte(n))
}
