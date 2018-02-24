package gateway

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hydrogen18/memlistener"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tmthrgd/pwned"
	"google.golang.org/grpc"
)

func testingClient() (c *pwned.Client, stop func()) {
	ln := memlistener.NewMemoryListener()

	srv := grpc.NewServer()

	s := pwned.NewServer(New())
	s.Attach(srv)

	go func() {
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

	return pwned.NewClient(cc), func() {
		cc.Close()
		srv.Stop()
		ln.Close()
	}
}

func TestSearch(t *testing.T) {
	t.Parallel()

	c, stop := testingClient()
	defer stop()

	count, err := c.Search(context.Background(), "password")
	require.NoError(t, err)
	assert.NotEqual(t, 0, count)
	t.Logf(`"password" leaked %d or more times`, count)
}

func TestSearchNotPresent(t *testing.T) {
	t.Parallel()

	c, stop := testingClient()
	defer stop()

	count, err := c.Search(context.Background(), "1cf71177e961aa2806822f381c752182")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
