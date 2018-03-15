package test

import (
	"net"
	"time"

	"github.com/hydrogen18/memlistener"
	"google.golang.org/grpc"
)

func TestingClient(attach func(*grpc.Server)) (c *grpc.ClientConn, stop func()) {
	ln := memlistener.NewMemoryListener()

	srv := grpc.NewServer()
	attach(srv)

	done := make(chan struct{})
	go func() {
		defer close(done)

		if err := srv.Serve(ln); err != nil && err != grpc.ErrServerStopped {
			panic(err)
		}
	}()

	cc, err := grpc.Dial("",
		grpc.WithDialer(func(addr string, dl time.Duration) (net.Conn, error) {
			return ln.Dial("test", addr)
		}),
		grpc.WithInsecure(),
	)
	if err != nil {
		panic(err)
	}

	return cc, func() {
		cc.Close()
		srv.Stop()
		ln.Close()
		<-done
	}
}
