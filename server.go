package pwned

import (
	"context"
	"crypto/sha1"

	pb "github.com/tmthrgd/pwned/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Ranger returns the results that match a given prefix.
// The rest of the password hash will be searched on the
// client.
//
// AppendResult should be used to format the returned data.
type Ranger interface {
	Range(ctx context.Context, prefix string) ([]byte, error)
}

// Lookup contains an optional method that Ranger's may
// implement to provide specific server side lookups.
//
// If not provided, Server will call Range and perform the
// search as the client would.
type Lookup interface {
	Ranger
	Lookup(ctx context.Context, digest [sha1.Size]byte) (count int, err error)
}

// Server represents a pwned.Searcher service.
type Server struct {
	ranger Ranger
	lookup Lookup
}

// NewServer creates a Server with the given Ranger.
func NewServer(ranger Ranger) *Server {
	lookup, _ := ranger.(Lookup)
	return &Server{
		ranger,
		lookup,
	}
}

type pbServer struct{ *Server }

// Attach registers the pwned.Searcher service to the
// given grpc.Server.
func (s *Server) Attach(srv *grpc.Server) {
	pb.RegisterSearcherServer(srv, pbServer{s})
}

func (s pbServer) Lookup(ctx context.Context, req *pb.LookupRequest) (*pb.LookupResponse, error) {
	if len(req.Digest) != sha1.Size {
		return nil, status.Error(codes.InvalidArgument, "digest is not SHA1")
	}

	var digest [sha1.Size]byte
	copy(digest[:], req.Digest)

	var (
		count int
		err   error
	)
	if s.lookup != nil {
		count, err = s.lookup.Lookup(ctx, digest)
	} else {
		prefix, suffix := SplitDigest(digest)

		var res []byte
		res, err = s.ranger.Range(ctx, prefix)

		count = searchSet(res, suffix)
	}

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.LookupResponse{
		Count: uint32(count),
	}, nil
}

func (s pbServer) Range(ctx context.Context, req *pb.RangeRequest) (*pb.RangeResponse, error) {
	if len(req.Prefix) != PrefixSize {
		return nil, status.Error(codes.InvalidArgument, "prefix is wrong size")
	}

	res, err := s.ranger.Range(ctx, req.Prefix)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if len(res)%(SuffixSize+1) != 0 {
		return nil, status.Error(codes.Internal, "invalid result set returned")
	}

	return &pb.RangeResponse{
		Results: res,
	}, nil
}
