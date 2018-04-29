// Package pwned provides a password checking client and server
// accessible via gRPC.
package pwned

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"math/bits"
	"strconv"
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

// SearchSet searches for suffix in set. It returns an estimate
// of the number of times it appears in the set.
func SearchSet(set []byte, suffix [SuffixSize]byte) int {
	// Benchmarks:
	//   minimum: N=381 -> 7.45µs ± 0%
	//   average: N=478 -> 9.40µs ± 2%
	//   maximum: N=584 -> 11.9µs ± 2%

	if len(set)%(SuffixSize+1) != 0 {
		panic("pwned: invariant invalid result set")
	}

	for i := 0; i < len(set); i += SuffixSize + 1 {
		if subtle.ConstantTimeCompare(suffix[:], set[i:i+SuffixSize]) != 1 {
			continue
		}

		if set[i+SuffixSize] > strconv.IntSize-1 {
			const maxInt = int(^uint(0) >> 1)
			return maxInt
		}

		return 1 << set[i+SuffixSize]
	}

	return 0
}

// Ranger returns the results that match a given prefix.
// The rest of the password hash will be searched on the
// client.
//
// AppendResult should be used to format the returned data.
type Ranger interface {
	Range(ctx context.Context, prefix string) ([]byte, error)
}
