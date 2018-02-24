package pwned

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"strconv"

	pb "github.com/tmthrgd/pwned/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

// Client wraps a grpc.ClientConn for use with the
// pwned.Searcher service.
type Client struct {
	cc *grpc.ClientConn
	pc pb.SearcherClient
}

// NewClient creates a Client from a given grpc.ClientConn.
func NewClient(cc *grpc.ClientConn) *Client {
	return &Client{
		cc: cc,
		pc: pb.NewSearcherClient(cc),
	}
}

// Close calls Close on the underlying grpc.ClientConn.
func (c *Client) Close() error {
	return c.cc.Close()
}

// Lookup returns the number of times the password occurs
// in the server's pwned password database. It returns
// (0, nil) if the password was not found in the database.
// The returned count will always be a power of two, less
// than or equal to the actual count.
//
// opts can be used to provide grpc.CallOption's to the
// underlying connection.
//
// Lookup reveals the password to the server so should be
// used with caution. It has the sole benefit of reducing
// network data transfers.
func (c *Client) Lookup(ctx context.Context, password string, opts ...grpc.CallOption) (count int, err error) {
	digest := sha1.Sum([]byte(password))

	resp, err := c.pc.Lookup(ctx, &pb.LookupRequest{
		Digest: digest[:],
	}, disableCompression(opts)...)
	if err != nil {
		return 0, err
	}

	return int(resp.GetCount()), nil
}

// Search returns the number of times the password occurs
// in the server's pwned password database. It returns
// (0, nil) if the password was not found in the database.
// The returned count will always be a power of two, less
// than or equal to the actual count.
//
// opts can be used to provide grpc.CallOption's to the
// underlying connection.
//
// Search relies on k-anonymity and does not reveal the
// password to the server. It requires the transfer of
// several KiB of data, but mitigates leaks of the password.
func (c *Client) Search(ctx context.Context, password string, opts ...grpc.CallOption) (count int, err error) {
	digest := sha1.Sum([]byte(password))
	prefix, suffix := SplitDigest(digest)

	resp, err := c.pc.Range(ctx, &pb.RangeRequest{
		Prefix: prefix,
	}, opts...)
	if err != nil {
		return 0, err
	}

	if len(resp.GetResults())%(SuffixSize+1) != 0 {
		return 0, errors.New("pwned: invalid result set returned")
	}

	return searchSet(resp.GetResults(), suffix), nil
}

// Benchmarks:
//   minimum: N=381 -> 7.45µs ± 0%
//   average: N=478 -> 9.40µs ± 2%
//   maximum: N=584 -> 11.9µs ± 2%
func searchSet(res []byte, suffix [SuffixSize]byte) int {
	if len(res)%(SuffixSize+1) != 0 {
		panic("pwned: invariant invalid result set")
	}

	for i := 0; i < len(res); i += SuffixSize + 1 {
		if subtle.ConstantTimeCompare(suffix[:], res[i:i+SuffixSize]) == 1 {
			if res[i+SuffixSize] > strconv.IntSize-1 {
				const maxInt = int(^uint(0) >> 1)
				return maxInt
			}

			return 1 << res[i+SuffixSize]
		}
	}

	return 0
}

// disableCompression does what it says on the tin. It's
// used to ensure the underlying transport does not
// introduce any compression side-channels. Otherwise it
// may be possible to recover secrets by watching packet
// sizes on the wire or monitoring execution time.
func disableCompression(opts []grpc.CallOption) []grpc.CallOption {
	return append(opts, grpc.UseCompressor(encoding.Identity))
}
