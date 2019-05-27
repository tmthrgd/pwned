package pwnedgrpc

import (
	"context"
	"crypto/sha1"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"tmthrgd.dev/go/pwned"
	pb "tmthrgd.dev/go/pwned/grpc/internal/proto"
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

	return int(resp.Count), nil
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
	prefix, suffix := pwned.SplitDigest(digest)

	resp, err := c.pc.Range(ctx, &pb.RangeRequest{
		Prefix: prefix,
	}, opts...)
	if err != nil {
		return 0, err
	}

	if len(resp.Results)%(pwned.SuffixSize+1) != 0 {
		return 0, errors.New("pwned: invalid result set returned")
	}

	return pwned.SearchSet(resp.Results, suffix), nil
}

// disableCompression does what it says on the tin. It's
// used to ensure the underlying transport does not
// introduce any compression side-channels. Otherwise it
// may be possible to recover secrets by watching packet
// sizes on the wire or monitoring execution time.
func disableCompression(opts []grpc.CallOption) []grpc.CallOption {
	return append(opts, grpc.UseCompressor(encoding.Identity))
}
