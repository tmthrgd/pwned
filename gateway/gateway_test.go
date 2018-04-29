package gateway

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tmthrgd/pwned/grpc"
	"github.com/tmthrgd/pwned/internal/test"
)

func TestSearch(t *testing.T) {
	t.Parallel()

	gw := New()

	c, stop := test.TestingClient(pwnedgrpc.NewServer(gw).Attach)
	defer stop()

	cc := pwnedgrpc.NewClient(c)

	count, err := cc.Search(context.Background(), "password")
	require.NoError(t, err)
	assert.NotEqual(t, 0, count)
	t.Logf(`"password" leaked %d or more times`, count)
}

func TestSearchNotPresent(t *testing.T) {
	t.Parallel()

	gw := New()

	c, stop := test.TestingClient(pwnedgrpc.NewServer(gw).Attach)
	defer stop()

	cc := pwnedgrpc.NewClient(c)

	count, err := cc.Search(context.Background(), "1cf71177e961aa2806822f381c752182")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
